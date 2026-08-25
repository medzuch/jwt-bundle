<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use FilesystemIterator;
use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Key\KeyLoader;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\CollectingLogger;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Key material is the one thing this bundle handles that must not be readable
 * anywhere else (K9): not in the compiled container, not in a container
 * parameter, not in an error, not in a log.
 *
 * The guarantee is made by construction — material stays an env reference or a
 * path all the way into a factory argument, and the factory runs when the
 * service is built — which is exactly the kind of guarantee that survives until
 * somebody adds a `setParameter()` or an `sprintf('%s', $source)`. So this
 * reads the artefacts rather than the code: the container Symfony wrote to
 * disk, the parameters `debug:container` prints, the message an unreadable key
 * throws, and the records a logger collected.
 *
 * Every secret below is generated per run and never leaves the test process.
 */
#[CoversClass(MedzuchJwtBundle::class)]
#[CoversClass(KeyLoader::class)]
final class KeyMaterialTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';

    /** @var array<string, string> */
    private static array $environment = [];

    /** @var array<string, string> */
    private static array $secrets = [];

    /** @var array{private: string, public: string}|null */
    private static ?array $encrypted = null;

    /** @var array{private: string, public: string}|null */
    private static ?array $ed25519 = null;

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    protected function tearDown(): void
    {
        foreach (array_keys(self::$environment) as $name) {
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }

        self::$environment = [];

        parent::tearDown();
    }

    #[TestDox('material given as an env reference never reaches the compiled container')]
    public function testEnvironmentMaterialStaysOutOfTheCompiledContainer(): void
    {
        $secrets = self::environment();

        self::bootKernel(['medzuch_jwt' => self::configuration(
            hmac: '%env(JWT_K9_SECRET)%',
            pemPrivate: '%env(JWT_K9_PEM)%',
            passphrase: '%env(JWT_K9_PASSPHRASE)%',
            jwkPrivate: '%env(JWT_K9_JWK)%',
        )]);

        // Round-tripped first, so what follows is a container that really did
        // build working keys out of those references rather than one that
        // dropped them: a container holding no secret because it holds no key
        // would pass every assertion below.
        foreach (['hs', 'rs', 'ed'] as $name) {
            self::assertSame('user-42', self::handler($name)->getUserBadgeFrom(self::issuer($name)->issue('user-42')->value)->getUserIdentifier());
        }

        $compiled = self::compiledContainer();

        foreach ($secrets as $name => $secret) {
            self::assertStringNotContainsString($secret, $compiled, sprintf('%s reached the compiled container', $name));
            // The reference did reach it, which is what makes the assertion
            // above about where the value went rather than about it never
            // having been configured.
            self::assertStringContainsString('env(' . $name . ')', $compiled, sprintf('%s is not referenced by the compiled container at all', $name));
        }
    }

    #[TestDox('material written into the configuration never becomes a container parameter')]
    public function testInlineMaterialNeverBecomesAParameter(): void
    {
        // The inline spelling is the one the guarantee is hardest to keep: the
        // value is already in the application's configuration, so the only
        // thing left to protect is that the bundle does not copy it somewhere
        // `debug:container --parameters` prints.
        $secrets = self::inlineSecrets();

        self::bootKernel(['medzuch_jwt' => self::configuration(
            hmac: $secrets['hmac'],
            pemPrivate: $secrets['pem'],
            passphrase: $secrets['passphrase'],
            jwkPrivate: $secrets['jwk'],
        )]);

        $parameters = json_encode(self::getContainer()->getParameterBag()->all(), \JSON_THROW_ON_ERROR);
        $printed = self::debugContainer(['--parameters' => true]);

        foreach ($secrets as $kind => $secret) {
            self::assertStringNotContainsString($secret, $parameters, sprintf('the %s is a container parameter', $kind));
            self::assertStringNotContainsString($secret, $printed, sprintf('the %s is printed by debug:container --parameters', $kind));
        }
    }

    #[TestDox('a value that is neither a path nor a document is not quoted back')]
    #[DataProvider('mangledDocuments')]
    public function testAMangledDocumentIsNotPrintedInTheError(string $material, string $needle, callable $load): void
    {
        // What reaches this branch is a key whose armour was lost somewhere
        // between the secret store and the configuration — so the value is
        // neither readable as a file nor recognisable as a document, and it is
        // still the key. An error naming it puts it in the log and on the
        // error page at once.
        try {
            $load($material);
            self::fail('a mangled document should not load');
        } catch (InvalidKeyException $e) {
            self::assertStringNotContainsString($needle, $e->getMessage());
            self::assertStringContainsString('not printed in case it is key material', $e->getMessage());
        }
    }

    #[TestDox('a path that cannot be read is quoted back, because that is the thing to fix')]
    public function testAnUnreadablePathIsStillNamed(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('"/no/such/directory/private.pem"');

        KeyLoader::signingKey('/no/such/directory/private.pem', 'RS256', null, null);
    }

    #[TestDox('nothing a verification logs carries the key it verified against')]
    public function testTheLogNeverCarriesKeyMaterial(): void
    {
        $secrets = self::inlineSecrets();

        $configuration = self::configuration(
            hmac: $secrets['hmac'],
            pemPrivate: $secrets['pem'],
            passphrase: $secrets['passphrase'],
            jwkPrivate: $secrets['jwk'],
        );
        $configuration['logger'] = 'test.logger';

        self::bootKernel(['medzuch_jwt' => $configuration]);

        // Both verdicts: an acceptance names the key it used, and a refusal is
        // where a message quoting whatever went wrong would be tempting.
        self::handler('hs')->getUserBadgeFrom(self::issuer('hs')->issue('user-42')->value);

        try {
            self::handler('hs')->getUserBadgeFrom(self::issuer('rs')->issue('user-42')->value);
        } catch (AuthenticationException) {
        }

        $logger = self::getContainer()->get('test.logger');
        self::assertInstanceOf(CollectingLogger::class, $logger);
        self::assertNotSame([], $logger->records, 'nothing was logged, so nothing was asserted');

        $recorded = json_encode($logger->records, \JSON_THROW_ON_ERROR);

        foreach ($secrets as $kind => $secret) {
            self::assertStringNotContainsString($secret, $recorded, sprintf('the %s was logged', $kind));
        }
    }

    /**
     * @return iterable<string, array{string, string, callable(string): mixed}>
     */
    public static function mangledDocuments(): iterable
    {
        $pem = self::freshKeypair()['private'];
        $jwk = json_encode(['kty' => 'OKP', 'crv' => 'Ed25519', 'alg' => 'EdDSA', 'x' => 'unused', 'd' => 'the-seed-nobody-else-has'], \JSON_THROW_ON_ERROR);

        yield 'a PEM that lost its armour' => [
            ltrim($pem, '-'),
            substr($pem, 40, 60),
            static fn(string $material): mixed => KeyLoader::signingKey($material, 'RS256', null, null),
        ];

        yield 'a JWK that lost its opening brace' => [
            ltrim($jwk, '{'),
            'the-seed-nobody-else-has',
            static fn(string $material): mixed => KeyLoader::signingKeyFromJwk($material, 'EdDSA', null),
        ];
    }

    /**
     * Everything Symfony wrote for this boot, as one string.
     *
     * The dumped container is several files — the container class, its
     * preloading and deprecation lists, the resource map — and a secret that
     * escaped could be in any of them, so the whole directory is read rather
     * than the one file this test happens to expect.
     */
    private static function compiledContainer(): string
    {
        $kernel = self::$kernel;
        self::assertInstanceOf(TestKernel::class, $kernel);

        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($kernel->getCacheDir(), FilesystemIterator::SKIP_DOTS),
        );

        $read = '';

        foreach ($files as $file) {
            self::assertInstanceOf(SplFileInfo::class, $file);

            if ($file->isFile()) {
                $read .= file_get_contents($file->getPathname());
            }
        }

        self::assertStringContainsString('medzuch_jwt.key.shared', $read, 'the cache directory holds no compiled container');

        return $read;
    }

    /**
     * @param array<string, mixed> $input
     */
    private static function debugContainer(array $input): string
    {
        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);

        $application = new Application($kernel);
        $application->setAutoExit(false);

        $tester = new CommandTester($application->find('debug:container'));
        $tester->execute($input + ['--no-debug' => true]);

        return $tester->getDisplay();
    }

    /**
     * The environment an application would provide, set for the duration of
     * one test and named so the assertions can look for the reference too.
     *
     * @return array<string, string>
     */
    private static function environment(): array
    {
        $secrets = self::inlineSecrets();

        self::$environment = [
            'JWT_K9_SECRET' => $secrets['hmac'],
            'JWT_K9_PEM' => $secrets['pem'],
            'JWT_K9_PASSPHRASE' => $secrets['passphrase'],
            'JWT_K9_JWK' => $secrets['jwk'],
        ];

        foreach (self::$environment as $name => $value) {
            putenv($name . '=' . $value);
            $_ENV[$name] = $value;
        }

        return self::$environment;
    }

    /**
     * The four secrets under test, generated once per class: a shared secret,
     * a passphrase-protected RSA private key, that passphrase, and an Ed25519
     * private JWK.
     *
     * @return array{hmac: string, pem: string, passphrase: string, jwk: string}
     */
    private static function inlineSecrets(): array
    {
        return [
            'hmac' => self::hmacSecret(),
            'pem' => self::encryptedKeypair()['private'],
            'passphrase' => self::passphrase(),
            'jwk' => self::ed25519()['private'],
        ];
    }

    private static function hmacSecret(): string
    {
        return self::$secrets['hmac'] ??= 'k9-' . bin2hex(random_bytes(24));
    }

    private static function passphrase(): string
    {
        return self::$secrets['passphrase'] ??= 'k9-passphrase-' . bin2hex(random_bytes(12));
    }

    /**
     * An RSA pair whose private half is encrypted, so the passphrase is a
     * secret the container has to carry as well as the key.
     *
     * @return array{private: string, public: string}
     */
    private static function encryptedKeypair(): array
    {
        if (isset(self::$encrypted)) {
            return self::$encrypted;
        }

        $resource = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        if (false === $resource || !openssl_pkey_export($resource, $private, self::passphrase())) {
            throw new RuntimeException('could not generate an encrypted keypair');
        }

        $details = openssl_pkey_get_details($resource);

        if (!is_array($details) || !is_string($details['key'])) {
            throw new RuntimeException('could not read the public key');
        }

        return self::$encrypted = ['private' => (string) $private, 'public' => $details['key']];
    }

    /**
     * The trait mints a fresh Ed25519 pair per call, which is what its other
     * callers want; here the two halves have to be each other's.
     *
     * @return array{private: string, public: string}
     */
    private static function ed25519(): array
    {
        return self::$ed25519 ??= self::ed25519Jwks('ed-2026');
    }

    /**
     * One key of every private spelling — a shared secret, an encrypted PEM,
     * a JWK — each with the half that verifies it, so every factory the bundle
     * registers for key material is exercised by one boot.
     *
     * @return array<string, mixed>
     */
    private static function configuration(string $hmac, string $pemPrivate, string $passphrase, string $jwkPrivate): array
    {
        $issuer = static fn(string $key): array => [
            'issuer' => self::ISSUER,
            'key' => $key,
            'client_id' => 'test-client',
            'audience' => self::AUDIENCE,
        ];

        $consumer = static fn(string $key, string $algorithm): array => [
            'issuer' => self::ISSUER,
            'audience' => self::AUDIENCE,
            'keys' => [$key],
            'allowed_algorithms' => [$algorithm],
        ];

        return [
            'keys' => [
                'shared' => ['hmac' => $hmac, 'algorithm' => 'HS256'],
                'rsa' => [
                    'pem_private' => $pemPrivate,
                    'pem_passphrase' => $passphrase,
                    'pem_public' => self::encryptedKeypair()['public'],
                    'algorithm' => 'RS256',
                ],
                'ed' => [
                    'jwk_private' => $jwkPrivate,
                    'jwk_public' => self::ed25519()['public'],
                    'algorithm' => 'EdDSA',
                    'kid' => 'ed-2026',
                ],
            ],
            'issuers' => [
                'hs' => $issuer('shared'),
                'rs' => $issuer('rsa'),
                'ed' => $issuer('ed'),
            ],
            'consumers' => [
                'hs' => $consumer('shared', 'HS256'),
                'rs' => $consumer('rsa', 'RS256'),
                'ed' => $consumer('ed', 'EdDSA'),
            ],
        ];
    }

    private static function issuer(string $name): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.' . $name);
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function handler(string $name): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.' . $name);
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }
}
