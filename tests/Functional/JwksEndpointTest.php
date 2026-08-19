<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Jwks\JwksController;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The published document, over HTTP, through the application's own route.
 *
 * The fixture publishes one RSA and one EC key, so the "no private material"
 * scan means something for both families rather than for the one that happens
 * to be everywhere else in this suite.
 */
#[CoversClass(JwksController::class)]
final class JwksEndpointTest extends WebTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const MAX_AGE = 600;

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration());
    }

    #[TestDox('the document is served to an unauthenticated caller, which is the whole point of it')]
    public function testServedAnonymously(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        self::assertResponseIsSuccessful();
        self::assertSame('application/jwk-set+json', $client->getResponse()->headers->get('Content-Type'));
    }

    #[TestDox('every configured key is published, with its kid, algorithm and use')]
    public function testPublishesEveryConfiguredKey(): void
    {
        $keys = self::document(self::createClient());

        self::assertCount(2, $keys);

        foreach ($keys as $jwk) {
            self::assertIsArray($jwk);
            self::assertSame('sig', $jwk['use'] ?? null, 'a verification key should say what it is for (RFC 7517 §4.2)');
            self::assertContains($jwk['kid'] ?? null, ['rsa-2026', 'ec-2026']);
            self::assertContains($jwk['alg'] ?? null, ['RS256', 'ES256']);
        }
    }

    #[TestDox('no private material reaches the document, for either key family')]
    public function testPublishesNoPrivateMaterial(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        $body = (string) $client->getResponse()->getContent();

        // "d" is the private exponent for RSA and the private scalar for EC;
        // the rest are the RSA CRT parameters. Any of them means the endpoint
        // is handing out a signing key in a document that still parses.
        foreach (['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"'] as $privateMember) {
            self::assertStringNotContainsString($privateMember, $body, 'the JWK Set must carry public parameters only');
        }
    }

    #[TestDox('the configured cache lifetime is the one served')]
    public function testCacheLifetimeIsConfigured(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        $cacheControl = (string) $client->getResponse()->headers->get('Cache-Control');

        self::assertStringContainsString('public', $cacheControl);
        // Distinct from the default on purpose: with 300 here, a wiring bug
        // that ignored the configured value would pass.
        self::assertStringContainsString('max-age=' . self::MAX_AGE, $cacheControl);
    }

    #[TestDox('a conditional request gets 304 rather than the document again')]
    public function testConditionalRequestIsNotModified(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        $etag = $client->getResponse()->getEtag();
        self::assertIsString($etag);

        $client->request('GET', '/.well-known/jwks.json', server: ['HTTP_IF_NONE_MATCH' => $etag]);

        self::assertSame(Response::HTTP_NOT_MODIFIED, $client->getResponse()->getStatusCode());
        self::assertSame('', $client->getResponse()->getContent());
    }

    /**
     * @return list<mixed>
     */
    private static function document(KernelBrowser $client): array
    {
        $client->request('GET', '/.well-known/jwks.json');

        $decoded = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertIsArray($decoded['keys'] ?? null);
        self::assertIsList($decoded['keys']);

        return $decoded['keys'];
    }

    /**
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        $rsa = self::keypair('rsa');
        $ec = self::keypair('ec', ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        return [
            'keys' => [
                'rsa' => ['pem_public' => $rsa['public'], 'algorithm' => 'RS256', 'kid' => 'rsa-2026'],
                'ec' => ['pem_public' => $ec['public'], 'algorithm' => 'ES256', 'kid' => 'ec-2026'],
            ],
            'jwks' => ['keys' => ['rsa', 'ec'], 'cache_max_age' => self::MAX_AGE],
        ];
    }
}
