<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Key\KeyLoader;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Asymmetric keys end to end: a token signed with a private PEM is verified
 * with the matching public one, through the container rather than by hand.
 *
 * Key material is generated per run rather than committed. A fixture keypair in
 * a repository is a keypair someone eventually uses in anger.
 */
#[CoversClass(KeyLoader::class)]
final class AsymmetricKeyTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    /** @var array<string, array{private: string, public: string}> */
    private static array $keypairs = [];

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

    /**
     * @return iterable<string, array{string, array{private_key_type: int, private_key_bits?: int, curve_name?: string}}>
     */
    public static function algorithms(): iterable
    {
        yield 'RS256' => ['RS256', ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]];
        yield 'ES256' => ['ES256', ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']];
    }

    /**
     * @param array<string, mixed> $options
     */
    #[DataProvider('algorithms')]
    #[TestDox('a token signed with a $algorithm private key verifies against its public half')]
    public function testAsymmetricRoundTrip(string $algorithm, array $options): void
    {
        $keypair = self::keypair($algorithm, $options);

        self::bootKernel(['medzuch_jwt' => self::configuration($algorithm, $keypair['private'], $keypair['public'])]);

        $token = self::issuer()->issue('user-42');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('a token signed with another key of the same algorithm is refused')]
    public function testWrongKeyIsRefused(): void
    {
        $mine = self::keypair('RS256', ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $theirs = self::freshKeypair(['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        self::bootKernel(['medzuch_jwt' => self::configuration('RS256', $theirs['private'], $mine['public'])]);

        $token = self::issuer()->issue('user-42');

        $this->expectException(BadCredentialsException::class);

        self::handler()->getUserBadgeFrom($token->value);
    }

    #[TestDox('a PEM can be a path as well as the key itself')]
    public function testPemFromFile(): void
    {
        $keypair = self::keypair('RS256', ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        self::bootKernel(['medzuch_jwt' => self::configuration(
            'RS256',
            self::writeToFile($keypair['private']),
            self::writeToFile($keypair['public']),
        )]);

        $token = self::issuer()->issue('user-42');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('a passphrase-protected private PEM is opened with the configured passphrase')]
    public function testEncryptedPem(): void
    {
        $resource = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($resource);

        self::assertTrue(openssl_pkey_export($resource, $private, 'la-clé'));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);
        self::assertIsString($details['key']);

        $configuration = self::configuration('RS256', $private, $details['key']);
        $configuration['keys']['signing'] += ['pem_passphrase' => 'la-clé'];

        self::bootKernel(['medzuch_jwt' => $configuration]);

        $token = self::issuer()->issue('user-42');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    /**
     * @return array{keys: array<string, array<string, string>>, issuers: array<string, mixed>, consumers: array<string, mixed>}
     */
    private static function configuration(string $algorithm, string $private, string $public): array
    {
        return [
            'keys' => [
                'signing' => ['pem_private' => $private, 'algorithm' => $algorithm],
                'verifying' => ['pem_public' => $public, 'algorithm' => $algorithm],
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

    /**
     * @param array<string, mixed> $options
     *
     * @return array{private: string, public: string}
     */
    private static function keypair(string $name, array $options): array
    {
        return self::$keypairs[$name] ??= self::freshKeypair($options);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array{private: string, public: string}
     */
    private static function freshKeypair(array $options): array
    {
        $resource = openssl_pkey_new($options);

        if (false === $resource) {
            throw new RuntimeException('could not generate a keypair');
        }

        if (!openssl_pkey_export($resource, $private)) {
            throw new RuntimeException('could not export the private key');
        }

        $details = openssl_pkey_get_details($resource);

        if (!is_array($details) || !is_string($details['key'])) {
            throw new RuntimeException('could not read the public key');
        }

        return ['private' => (string) $private, 'public' => $details['key']];
    }

    private static function writeToFile(string $pem): string
    {
        $path = tempnam(sys_get_temp_dir(), 'jwt-bundle-key-');

        if (false === $path || false === file_put_contents($path, $pem)) {
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
