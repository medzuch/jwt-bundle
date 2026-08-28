<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Oidc\MetadataController;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The metadata document this application publishes about itself (K8), over HTTP
 * and through the application's own route.
 *
 * Published beside the JWK Set it points at, which is the shape a real
 * deployment has: the document exists to tell a reader where the keys are, so a
 * fixture that published one without the other would be testing half a claim.
 *
 * What this suite does *not* assert is that the document is a complete
 * authorization-server description. It cannot be: running such a server is a
 * non-goal, so everything past `issuer` and `jwks_uri` arrives from `extra` and
 * is the application's to get right. What the bundle owes is that the two
 * members it does fill in are correct, that a document missing what RFC 8414
 * requires is refused before it is served, and that the whole thing is readable
 * without credentials.
 */
#[CoversClass(MetadataController::class)]
final class MetadataEndpointTest extends WebTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const ISSUER = 'https://api.test';

    private const JWKS_URI = self::ISSUER . '/.well-known/jwks.json';

    private const PATH = '/.well-known/oauth-authorization-server';

    private const MAX_AGE = 600;

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? null;

        return new SecuredKernel(is_array($config) ? $config : self::configuration());
    }

    #[TestDox('the document is served to an unauthenticated caller, which is the whole point of it')]
    public function testServedAnonymously(): void
    {
        $client = self::createClient();
        $client->request('GET', self::PATH);

        self::assertResponseIsSuccessful();
        self::assertSame(self::ISSUER, self::json($client)['issuer'] ?? null);
    }

    #[TestDox('a sibling path under the same firewall and the same catch-all rule is refused')]
    public function testTheExemptionIsWhatServesTheDocument(): void
    {
        // Without this the suite could not tell "the access rule exempts this
        // path" from "nothing was guarding it anyway", and the exemption could
        // be dropped with every other row still green.
        $client = self::createClient();
        $client->request('GET', '/.well-known/probe');

        self::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    #[TestDox('the two members the bundle knows are the two it fills in')]
    public function testTheBundleFillsInWhatItKnows(): void
    {
        $client = self::createClient();
        $client->request('GET', self::PATH);

        $document = self::json($client);

        self::assertSame(self::ISSUER, $document['issuer'] ?? null);
        self::assertSame(self::JWKS_URI, $document['jwks_uri'] ?? null);
    }

    #[TestDox('everything else is carried through from extra, untouched')]
    public function testExtraIsCarriedThrough(): void
    {
        // Including a nested structure and a member the bundle has no opinion
        // about: `extra` is the seam for an authorization server this package
        // is not, so anything it hands over has to arrive as written.
        $client = self::createClient();
        $client->request('GET', self::PATH);

        $document = self::json($client);

        self::assertSame(['code'], $document['response_types_supported'] ?? null);
        self::assertSame(self::ISSUER . '/oauth/token', $document['token_endpoint'] ?? null);
        self::assertSame(['client_secret_basic', 'private_key_jwt'], $document['token_endpoint_auth_methods_supported'] ?? null);
    }

    #[TestDox('the document is cacheable and revalidates on its own content')]
    public function testCaching(): void
    {
        $client = self::createClient();
        $client->request('GET', self::PATH);

        $response = $client->getResponse();
        $etag = $response->getEtag();

        self::assertNotNull($etag);
        self::assertSame(self::MAX_AGE, $response->getMaxAge());
        self::assertTrue($response->headers->hasCacheControlDirective('public'));

        self::ensureKernelShutdown();
        $client = self::createClient();
        $client->request('GET', self::PATH, server: ['HTTP_IF_NONE_MATCH' => $etag]);

        self::assertSame(Response::HTTP_NOT_MODIFIED, $client->getResponse()->getStatusCode());
    }

    #[TestDox('an application that configures no issuer publishes no endpoint')]
    public function testNothingIsPublishedWithoutAnIssuer(): void
    {
        // The section carries defaults so the tree can describe it, which would
        // otherwise mean every application serving `{}` at a well-known path.
        self::bootKernel(['medzuch_jwt' => self::configuration(issuer: null)]);

        self::assertFalse(self::getContainer()->has('medzuch_jwt.metadata_controller'));
    }

    #[TestDox('a document without response_types_supported fails at container build')]
    public function testTheRequiredMemberIsRefused(): void
    {
        // RFC 8414 §2 requires it and this bundle cannot supply it, so the
        // choice is between refusing and serving a document that claims
        // conformance it does not have.
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/without "response_types_supported", which RFC 8414 §2 requires/');

        self::bootKernel(['medzuch_jwt' => self::configuration(extra: ['token_endpoint' => self::ISSUER . '/oauth/token'])]);
    }

    #[DataProvider('shadowedMembers')]
    #[TestDox('an extra member shadowing an option above it fails at container build: $member')]
    public function testExtraCannotShadowTheOptions(string $member): void
    {
        // Two spellings of one member could disagree, and JSON may only carry
        // the answer once — so which one wins would be an ordering detail
        // nobody wrote down.
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/which is the option above it/');

        self::bootKernel(['medzuch_jwt' => self::configuration(
            extra: ['response_types_supported' => ['code'], $member => 'https://elsewhere.test'],
        )]);
    }

    /** @return iterable<string, array{string}> */
    public static function shadowedMembers(): iterable
    {
        yield 'issuer' => ['issuer'];
        yield 'jwks_uri' => ['jwks_uri'];
    }

    #[DataProvider('plaintext')]
    #[TestDox('an identifier that is not https fails at container build: $_dataName')]
    public function testPlaintextIsRefused(string $issuer): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/is not https/');

        self::bootKernel(['medzuch_jwt' => self::configuration(issuer: $issuer)]);
    }

    /** @return iterable<string, array{string}> */
    public static function plaintext(): iterable
    {
        yield 'plaintext' => ['http://api.test'];
        yield 'plaintext, shouted' => ['HTTP://api.test'];
        yield 'no scheme at all' => ['api.test'];
    }

    #[TestDox('a blank identifier fails at container build rather than publishing an empty one')]
    public function testBlankIssuerIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/has a blank issuer; omit it instead/');

        self::bootKernel(['medzuch_jwt' => self::configuration(issuer: '   ')]);
    }

    #[TestDox('a jwks_uri that is not https fails at container build too')]
    public function testPlaintextJwksUriIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/has an jwks_uri that is not https/');

        self::bootKernel(['medzuch_jwt' => self::configuration(jwksUri: 'http://api.test/.well-known/jwks.json')]);
    }

    #[TestDox('an identifier assembled from the environment is not judged at build')]
    public function testEnvironmentIssuerIsNotJudgedAtBuild(): void
    {
        // The same exemption `remote_jwks` makes, for the same reason: there is
        // nothing to read until the container is compiled, and refusing it
        // would make the recommended spelling impossible.
        putenv('JWT_TEST_METADATA_ISSUER=' . self::ISSUER);

        try {
            self::bootKernel(['medzuch_jwt' => self::configuration(issuer: '%env(JWT_TEST_METADATA_ISSUER)%')]);

            self::assertTrue(self::getContainer()->has('medzuch_jwt.metadata_controller'));
        } finally {
            putenv('JWT_TEST_METADATA_ISSUER');
        }
    }

    /** @return array<string, mixed> */
    private static function json(KernelBrowser $client): array
    {
        $decoded = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param array<string, mixed>|null $extra
     *
     * @return array<string, mixed>
     */
    private static function configuration(
        ?string $issuer = self::ISSUER,
        ?string $jwksUri = self::JWKS_URI,
        ?array $extra = null,
    ): array {
        return [
            'keys' => [
                'published' => ['pem_public' => self::keypair('metadata')['public'], 'algorithm' => 'RS256', 'kid' => 'api-2026'],
            ],
            // Published together, because the document exists to point at it.
            'jwks' => ['keys' => ['published']],
            'metadata' => [
                'issuer' => $issuer,
                'jwks_uri' => $jwksUri,
                'cache_max_age' => self::MAX_AGE,
                'extra' => $extra ?? [
                    'response_types_supported' => ['code'],
                    'token_endpoint' => self::ISSUER . '/oauth/token',
                    'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'private_key_jwt'],
                ],
            ],
        ];
    }
}
