<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Key\KeyLoader;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Keys configured as JWKs, which is what EdDSA is: RFC 8037 defines Ed25519 as
 * a JWK and there is no PEM spelling of it, so this is the source that makes
 * the algorithm reachable at all.
 *
 * A JWK says its own `alg`, `kid` and `use`, and so does the configuration
 * pointing at it. The tests below are mostly about what happens when the two
 * disagree, because that is the case a document alone cannot settle: the
 * container was built from the configuration.
 */
#[CoversClass(KeyLoader::class)]
final class JwkKeyTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    /** @var list<string> */
    private static array $files = [];

    public static function tearDownAfterClass(): void
    {
        foreach (self::$files as $file) {
            @unlink($file);
        }

        self::$files = [];
    }

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('an EdDSA token is signed and verified through Ed25519 JWKs')]
    public function testEdDsaRoundTrip(): void
    {
        $pair = self::ed25519Jwks('2026-08');

        self::bootKernel(['medzuch_jwt' => self::configuration('EdDSA', $pair['private'], $pair['public'], '2026-08')]);

        $token = self::issuer()->issue('user-42');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('an RSA key can be given as a JWK instead of a PEM')]
    public function testRsaFromJwk(): void
    {
        $pair = self::rsaJwks('2026-08');

        self::bootKernel(['medzuch_jwt' => self::configuration('RS256', $pair['private'], $pair['public'], '2026-08')]);

        $token = self::issuer()->issue('user-42');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('a JWK can be a path as well as the document itself')]
    public function testJwkFromFile(): void
    {
        $pair = self::ed25519Jwks('2026-08');

        self::bootKernel(['medzuch_jwt' => self::configuration(
            'EdDSA',
            self::writeToFile($pair['private']),
            self::writeToFile($pair['public']),
            '2026-08',
        )]);

        $token = self::issuer()->issue('user-42');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('a private JWK behind jwk_public is refused rather than published')]
    public function testPrivateDocumentAsPublicHalf(): void
    {
        $pair = self::ed25519Jwks('2026-08');
        $config = self::configuration('EdDSA', $pair['private'], $pair['public'], '2026-08');
        $config['keys']['verifying']['jwk_public'] = $pair['private'];

        self::bootKernel(['medzuch_jwt' => $config]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/has a "d".*gives? away the key that signs/s');

        self::getContainer()->get('medzuch_jwt.key.verifying.verification');
    }

    #[TestDox('a public JWK behind jwk_private is refused rather than failing at the first token')]
    public function testPublicDocumentAsPrivateHalf(): void
    {
        $pair = self::ed25519Jwks('2026-08');
        $config = self::configuration('EdDSA', $pair['private'], $pair['public'], '2026-08');
        $config['keys']['signing']['jwk_private'] = $pair['public'];

        self::bootKernel(['medzuch_jwt' => $config]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/has no "d"/');

        self::getContainer()->get('medzuch_jwt.key.signing');
    }

    #[TestDox('a JWK stating another algorithm than the configuration is refused')]
    public function testAlgorithmDisagreement(): void
    {
        // The document is an Ed25519 key claiming ES256. Refused for what it
        // says, not for what it holds: the container was built for EdDSA, and
        // a key that turned out to be something else would make every
        // build-time answer about it wrong.
        $pair = self::ed25519Jwks('2026-08');
        $config = self::configuration('EdDSA', self::restated($pair['private'], ['alg' => 'ES256']), $pair['public'], '2026-08');

        self::bootKernel(['medzuch_jwt' => $config]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/states alg "ES256" while the configuration says "EdDSA"/');

        self::getContainer()->get('medzuch_jwt.key.signing');
    }

    #[TestDox('a JWK carrying a kid the configuration does not declare is refused (DEC-5)')]
    public function testUndeclaredKid(): void
    {
        $pair = self::ed25519Jwks('2026-08');
        $config = self::configuration('EdDSA', $pair['private'], $pair['public'], null);

        self::bootKernel(['medzuch_jwt' => $config]);

        // Silently taking the document's kid would leave the configuration
        // describing an anonymous key while tokens carry the id — and the
        // build-time check for keys a token cannot tell apart reads the
        // configuration.
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/states kid "2026-08" while the configuration says nothing/');

        self::getContainer()->get('medzuch_jwt.key.signing');
    }

    #[TestDox('a JWK and a configuration naming different kids are refused')]
    public function testKidDisagreement(): void
    {
        $pair = self::ed25519Jwks('2026-08');
        $config = self::configuration('EdDSA', $pair['private'], $pair['public'], '2025-07');

        self::bootKernel(['medzuch_jwt' => $config]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/states kid "2026-08" while the configuration says "2025-07"/');

        self::getContainer()->get('medzuch_jwt.key.signing');
    }

    #[TestDox('a kid the document leaves out is taken from the configuration')]
    public function testConfiguredKidFillsTheDocument(): void
    {
        $pair = self::ed25519Jwks(null);
        $config = self::configuration('EdDSA', $pair['private'], $pair['public'], '2026-08');

        self::bootKernel(['medzuch_jwt' => $config]);

        $key = self::getContainer()->get('medzuch_jwt.key.verifying.verification');
        self::assertInstanceOf(\Medzuch\Jwt\Key\Key::class, $key);

        self::assertSame('2026-08', $key->kid());
        self::assertSame('sig', $key->use()?->value);
    }

    #[TestDox('a JWK Set where one key belongs names the mistake')]
    public function testJwkSetIsNotAKeySource(): void
    {
        $pair = self::ed25519Jwks('2026-08');
        $config = self::configuration('EdDSA', $pair['private'], $pair['public'], '2026-08');
        $config['keys']['verifying']['jwk_public'] = sprintf('{"keys": [%s]}', $pair['public']);

        self::bootKernel(['medzuch_jwt' => $config]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessageMatches('/is a JWK Set .*not a key source; name one key from it/');

        self::getContainer()->get('medzuch_jwt.key.verifying.verification');
    }

    /**
     * @return array{private: string, public: string}
     */
    private static function rsaJwks(string $kid): array
    {
        $pem = self::keypair('rsa');
        $private = RsaPrivateKey::fromPem($pem['private'], 'RS256', $kid);

        return [
            'private' => self::encodeJwk($private->toJwk()),
            'public' => self::encodeJwk($private->toPublicKey()->toJwk()),
        ];
    }

    /**
     * @param array<string, mixed> $members
     */
    private static function restated(string $jwk, array $members): string
    {
        $decoded = json_decode($jwk, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return self::encodeJwk($members + $decoded);
    }

    /**
     * @return array{keys: array<string, array<string, string|null>>, issuers: array<string, mixed>, consumers: array<string, mixed>}
     */
    private static function configuration(string $algorithm, string $private, string $public, ?string $kid): array
    {
        return [
            'keys' => [
                'signing' => ['jwk_private' => $private, 'algorithm' => $algorithm, 'kid' => $kid],
                'verifying' => ['jwk_public' => $public, 'algorithm' => $algorithm, 'kid' => $kid],
            ],
            'issuers' => [
                'default' => [
                    'issuer' => 'https://issuer.test',
                    'key' => 'signing',
                    'client_id' => 'test-client',
                    'audience' => 'https://api.test',
                ],
            ],
            'consumers' => [
                'api' => [
                    'issuer' => 'https://issuer.test',
                    'audience' => 'https://api.test',
                    'keys' => ['verifying'],
                    'allowed_algorithms' => [$algorithm],
                ],
            ],
        ];
    }

    private static function writeToFile(string $jwk): string
    {
        $path = tempnam(sys_get_temp_dir(), 'jwt-bundle-jwk-');

        if (false === $path || false === file_put_contents($path, $jwk)) {
            throw new RuntimeException('could not write a key file');
        }

        self::$files[] = $path;

        return $path;
    }

    private static function issuer(): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }
}
