<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Jwks\JwksController;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Rotation is a configuration move, not a feature: an issuer signs with one
 * key while a consumer accepts several, so a new key can start signing while
 * tokens from the old one are still in flight.
 *
 * What makes the overlap work is `kid` — without it the resolver takes the
 * first key bound to the algorithm and never tries the second, which is why
 * the configuration refuses that shape (DEC-5).
 */
#[CoversClass(JwksController::class)]
final class KeyRotationTest extends WebTestCase
{
    use RestoresExceptionHandler;

    /** @var array<string, array{private: string, public: string}> */
    private static array $keypairs = [];

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration());
    }

    #[TestDox('a token signed by the retired key still verifies while both are accepted')]
    public function testTokensFromBothKeysVerifyDuringOverlap(): void
    {
        self::bootKernel();

        foreach (['default', 'previous'] as $issuer) {
            $token = self::issuer($issuer)->issue('user-42');

            self::assertSame(
                'user-42',
                self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier(),
                sprintf('a token signed by the "%s" key should verify during the overlap', $issuer),
            );
        }
    }

    #[TestDox('the published JWK Set carries both accepted keys, by kid')]
    public function testJwksPublishesAcceptedKeys(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        self::assertResponseIsSuccessful();
        self::assertSame('application/jwk-set+json', $client->getResponse()->headers->get('Content-Type'));

        $document = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        self::assertIsArray($document['keys'] ?? null);

        $kids = array_map(static fn(mixed $jwk): mixed => is_array($jwk) ? ($jwk['kid'] ?? null) : null, $document['keys']);
        sort($kids);

        self::assertSame(['2025-07', '2026-01'], $kids);
    }

    #[TestDox('no private material reaches the published document')]
    public function testJwksPublishesNoPrivateMaterial(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        $body = (string) $client->getResponse()->getContent();

        // "d" is the RSA private exponent; its presence would mean the endpoint
        // is handing out the signing key in a document that still parses.
        foreach (['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"'] as $privateMember) {
            self::assertStringNotContainsString($privateMember, $body, 'the JWK Set must carry public parameters only');
        }
    }

    #[TestDox('the document is cacheable, because public keys are public')]
    public function testJwksIsCacheable(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        $cacheControl = (string) $client->getResponse()->headers->get('Cache-Control');

        self::assertStringContainsString('public', $cacheControl);
        self::assertStringContainsString('max-age=300', $cacheControl);
    }

    private static function issuer(string $name): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.' . $name);
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * The shape of a rotation half-way through: a new key signing, the previous
     * one still accepted, both published.
     *
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        $current = self::keypair('current');
        $previous = self::keypair('previous');

        return [
            'keys' => [
                'current_private' => ['pem_private' => $current['private'], 'algorithm' => 'RS256', 'kid' => '2026-01'],
                'current' => ['pem_public' => $current['public'], 'algorithm' => 'RS256', 'kid' => '2026-01'],
                'previous_private' => ['pem_private' => $previous['private'], 'algorithm' => 'RS256', 'kid' => '2025-07'],
                'previous' => ['pem_public' => $previous['public'], 'algorithm' => 'RS256', 'kid' => '2025-07'],
            ],
            'issuers' => [
                // The application has one issuer; `previous` exists only so a
                // test can mint what a token issued before the rotation looks
                // like, without keeping a token fixture around.
                'default' => self::issuerConfig('current_private'),
                'previous' => self::issuerConfig('previous_private'),
            ],
            'consumers' => [
                'api' => [
                    'issuer' => 'https://issuer.test',
                    'audience' => 'https://api.test',
                    'keys' => ['current', 'previous'],
                    'allowed_algorithms' => ['RS256'],
                ],
            ],
            'jwks' => ['keys' => ['current', 'previous']],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function issuerConfig(string $key): array
    {
        return [
            'issuer' => 'https://issuer.test',
            'key' => $key,
            'client_id' => 'test-client',
            'audience' => 'https://api.test',
        ];
    }

    /**
     * @return array{private: string, public: string}
     */
    private static function keypair(string $name): array
    {
        return self::$keypairs[$name] ??= self::freshKeypair();
    }

    /**
     * @return array{private: string, public: string}
     */
    private static function freshKeypair(): array
    {
        $resource = openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        if (false === $resource || !openssl_pkey_export($resource, $private)) {
            throw new RuntimeException('could not generate a keypair');
        }

        $details = openssl_pkey_get_details($resource);

        if (!is_array($details) || !is_string($details['key'])) {
            throw new RuntimeException('could not read the public key');
        }

        return ['private' => (string) $private, 'public' => $details['key']];
    }
}
