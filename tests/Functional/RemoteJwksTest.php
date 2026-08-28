<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use InvalidArgumentException;
use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Primitives\SystemClock;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Oidc\DiscoveredJwksResolver;
use Medzuch\JwtBundle\Oidc\MetadataController;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Tests\Functional\App\ArrayCache;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsVerification;
use Medzuch\JwtBundle\Tests\Functional\App\StubHttpClient;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use Medzuch\JwtBundle\Tests\Functional\App\TransportFailure;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Verification against a key set the application does not hold: the issuer
 * publishes it, this application fetches and caches it, and a key rotated to
 * after the last deploy still verifies (K5).
 *
 * Paired with local keys it is the outage story too (K6) — the local set is
 * tried first, so an unreachable identity provider cannot stop tokens signed
 * with keys already configured here.
 *
 * Both ways of naming the set are here (K7): a `uri` the application fixes, and
 * a `discovery` identifier it reads the endpoint from. They differ in one hop
 * and in what has to be checked before that hop is trusted, and nowhere else —
 * which is why the two share a harness rather than a file each.
 *
 * No test here touches the network. The identity provider is a PSR-18 double
 * that answers what it is told and records what was asked, because what has to
 * be asserted is when the fetch happens, not that HTTP works.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class RemoteJwksTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const URI = 'https://idp.test/.well-known/jwks.json';

    private const ISSUER = 'https://idp.test';

    private const DISCOVERY = self::ISSUER . '/.well-known/openid-configuration';

    /**
     * The service ids an application brings: Symfony registers `psr18.http_client`
     * once `psr/http-client` is installed, and `cache.app` is there by default.
     * Aliased to doubles so the branch that names neither can be built.
     *
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : [], [
            'psr18.http_client' => 'test.http_client',
            'cache.app' => 'test.cache_pool',
        ]);
    }

    #[TestDox('a token signed with a key only the issuer publishes verifies')]
    public function testRemoteKeyVerifies(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);
        self::publish();

        self::assertSame('user-42', self::verify(self::token('remote')));
        self::assertSame([self::URI], self::client()->requested);
    }

    #[TestDox('a set naming no services at all is built from the Symfony ones the defaults point at')]
    public function testDefaultWiring(): void
    {
        // Nothing but a URI, which is what the README advertises. This is the
        // branch where a wiring mistake would be silent: the other tests name
        // every service, so they never construct the wrapped PSR-6 pool, and
        // never ask the client to be its own PSR-17 factory.
        self::bootKernel(['medzuch_jwt' => self::configuration(set: ['http_client' => null, 'cache' => null])]);
        self::publish();

        self::assertSame('user-42', self::verify(self::token('remote')));
        self::assertSame([self::URI], self::client()->requested);

        // The pool, not the PSR-16 double: the default path wraps `cache.app`.
        self::assertNotSame([], self::pool()->getValues());
    }

    #[TestDox('the document is fetched once and served from the cache after that')]
    public function testDocumentIsCached(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);
        self::publish();

        $token = self::token('remote');
        self::verify($token);
        self::verify($token);

        self::assertCount(1, self::client()->requested, 'the second verification should not touch the network');
    }

    #[TestDox('the configured cache lifetime is the one the document is stored with')]
    public function testConfiguredTtlReachesTheCache(): void
    {
        // 900, not the 300 default: a resolver built with its own defaults
        // would pass this test if the assertion named the default.
        self::bootKernel(['medzuch_jwt' => self::configuration(['cache_ttl' => 900])]);
        self::publish();
        self::verify(self::token('remote'));

        self::assertContains(900, array_values(self::cache()->ttls));
    }

    #[TestDox('a response larger than the configured ceiling is refused before it is parsed')]
    public function testBodyCeiling(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['max_body_bytes' => 64])]);
        self::publish();

        // The cause, not just the refusal: every failure here arrives as the
        // same BadCredentialsException, so a token rejected for an unrelated
        // reason would pass a test that only named the outer exception.
        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertStringContainsString('exceeds the 64-byte limit', $cause->getMessage());
    }

    #[TestDox('an unreachable issuer does not stop tokens signed with keys this application holds (K6)')]
    public function testLocalKeysSurviveAnOutage(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(consumerKeys: ['local'], keys: [
            'local' => ['pem_public' => self::keypair('local')['public'], 'algorithm' => 'RS256', 'kid' => 'local-2026'],
        ])]);
        self::client()->goesOffline();

        self::assertSame('user-42', self::verify(self::token('local')));
        self::assertSame([], self::client()->requested, 'a key in the local set is not worth a round trip');
    }

    #[TestDox('a rotated key is picked up even when the local set is the one configured')]
    public function testRemoteKeyResolvesAlongsideLocalOnes(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(consumerKeys: ['local'], keys: [
            'local' => ['pem_public' => self::keypair('local')['public'], 'algorithm' => 'RS256', 'kid' => 'local-2026'],
        ])]);
        self::publish();

        self::assertSame('user-42', self::verify(self::token('remote')));

        // What separates this from the outage case above: the key was not
        // local, so the round trip had to happen.
        self::assertSame([self::URI], self::client()->requested);
    }

    #[TestDox('with the issuer unreachable and no local key, the token is refused as a credential')]
    public function testOutageWithoutLocalKeys(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);
        self::client()->goesOffline();

        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertInstanceOf(TransportFailure::class, $cause->getPrevious(), 'the transport failure should still be readable under the credential error');

        // And announced as what it is. A caller sees a refused credential
        // either way; whoever is on call needs to know this one is not about
        // the token, and it is the only reason worth paging on.
        $listener = self::getContainer()->get('test.verification_listener');
        self::assertInstanceOf(RecordsVerification::class, $listener);
        self::assertCount(1, $listener->rejected);
        self::assertSame(RejectionReason::KeysUnavailable, $listener->rejected[0]->reason);
    }

    #[TestDox('tokens naming a kid the issuer never published cost one fetch, not one each')]
    public function testUnknownKidsDoNotAmplify(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['min_refresh' => 60])]);
        self::publish();

        $unknown = self::token('local');
        $fetches = self::attempts($unknown, 3);

        // One fetch for the document, and none after it: a set fetched this
        // instant cannot have grown a key since, and a stream of tokens bearing
        // kids the issuer never published would otherwise be an amplifier
        // pointed at the endpoint. Rotation is still picked up — the window
        // reopening is what the next test is about.
        self::assertSame([1, 1, 1], $fetches);
    }

    #[TestDox('the configured refresh window is the one applied, and time reopens it')]
    public function testConfiguredRefreshWindowReachesTheResolver(): void
    {
        // 30, not the 60 default: a resolver built with its own default would
        // still be throttled at the instant this test moves to, so the window
        // being the configured one is what the assertion turns on.
        $config = self::configuration(['min_refresh' => 30]);
        $config['clock'] = 'test.frozen_clock';

        self::bootKernel(['medzuch_jwt' => $config]);
        self::publish();

        $unknown = self::token('local');
        $throttled = self::attempts($unknown, 2);
        self::assertSame($throttled[0], $throttled[1]);

        self::clock()->tick(new DateInterval('PT45S'));

        self::assertGreaterThan($throttled[1], self::attempts($unknown, 1)[0], 'past the window, an unknown kid is worth another look');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function uris(): iterable
    {
        yield 'plaintext' => ['http://idp.test/jwks.json'];
        // The spellings a check written against the obvious one lets through.
        yield 'plaintext, shouted' => ['HTTP://idp.test/jwks.json'];
        yield 'another scheme entirely' => ['ftp://idp.test/jwks.json'];
        yield 'no scheme at all' => ['idp.test/jwks.json'];
    }

    #[DataProvider('uris')]
    #[TestDox('a jwks_uri that is not https fails at container build: $_dataName')]
    public function testNonHttpsUriIsRefused(string $uri): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/not verification keys/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['uri' => $uri])]);
    }

    #[TestDox('a jwks_uri assembled from the environment is left for the library to judge')]
    public function testEnvironmentUriIsNotJudgedAtBuild(): void
    {
        // There is nothing to read at build time — the value is a placeholder
        // until the container is compiled — and refusing it would make the
        // recommended way of configuring a URI impossible.
        putenv('JWT_TEST_JWKS_URI=' . self::URI);

        try {
            self::bootKernel(['medzuch_jwt' => self::configuration(['uri' => '%env(JWT_TEST_JWKS_URI)%'])]);
            self::publish();

            self::assertSame('user-42', self::verify(self::token('remote')));
            self::assertSame([self::URI], self::client()->requested);
        } finally {
            putenv('JWT_TEST_JWKS_URI');
        }
    }

    #[TestDox('a consumer naming a remote set that does not exist fails at container build')]
    public function testUnknownRemoteSet(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/remote JWK Set "typo"/');

        self::bootKernel(['medzuch_jwt' => self::configuration(consumer: ['remote_jwks' => 'typo'])]);
    }

    #[TestDox('a consumer with neither keys nor a remote set fails at container build')]
    public function testConsumerWithoutAnyKeySource(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/nothing to verify with/');

        self::bootKernel(['medzuch_jwt' => self::configuration(consumer: ['remote_jwks' => null])]);
    }

    #[TestDox('naming both a PSR-16 cache and a PSR-6 pool fails at container build')]
    public function testTwoCaches(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/names both a PSR-16 cache and a PSR-6 pool/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['cache_pool' => 'cache.app'])]);
    }

    #[TestDox('an allowed algorithm with no local key is fine once a remote set can supply one')]
    public function testAllowlistIsNotJudgedAgainstLocalKeysAlone(): void
    {
        // Without a remote set this is the "could never be verified" refusal:
        // the allowlist names an algorithm nothing local is bound to. With one,
        // the question has no build-time answer — the issuer may rotate to it.
        self::bootKernel(['medzuch_jwt' => self::configuration(['uri' => self::URI], algorithms: ['RS256', 'ES256'])]);

        self::assertTrue(self::getContainer()->has('medzuch_jwt.handler.partner'));
    }

    #[TestDox('an issuer identifier is enough: the endpoint is read from its metadata (K7)')]
    public function testDiscoveredKeyVerifies(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::announce();
        self::publish();

        self::assertSame('user-42', self::verify(self::token('remote')));

        // The order is the assertion, not just the pair: the endpoint cannot
        // be fetched before the document that says where it is.
        self::assertSame([self::DISCOVERY, self::URI], self::client()->requested);
    }

    #[TestDox('the metadata is fetched once, not once per verification')]
    public function testDiscoveryIsCached(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::announce();
        self::publish();

        $token = self::token('remote');
        self::verify($token);
        self::verify($token);

        self::assertSame([self::DISCOVERY, self::URI], self::client()->requested, 'the second verification should not touch either endpoint');
    }

    #[TestDox('a resolver that did not do the asking reads the endpoint from the cache')]
    public function testDiscoveryIsCachedBeyondOneResolver(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::announce();
        self::publish();
        self::verify(self::token('remote'));

        $asked = self::client()->requested;

        // The container's resolver holds the endpoint for its own lifetime, so
        // a second verification through it proves nothing about the cache —
        // the test above passes with the cache write removed entirely. A fresh
        // instance is the next request, which is where a document that was
        // never written down costs a round trip to the issuer every time.
        $next = new DiscoveredJwksResolver(self::ISSUER, self::client(), self::client(), self::cache(), new SystemClock());
        $next->resolve(['kid' => 'partner-2026']);

        self::assertSame($asked, self::client()->requested, 'neither endpoint should be asked a second time');
    }

    #[TestDox('a metadata document naming a different issuer is refused (OIDC Discovery §4.3)')]
    public function testDiscoveryIssuerMismatch(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::announce(issuer: 'https://attacker.test');
        self::publish();

        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertStringContainsString('states issuer "https://attacker.test"', $cause->getMessage());

        // And the keys it pointed at were never asked for. Without the issuer
        // check this document is a redirect: whoever answers the well-known
        // path chooses which keys this application trusts.
        self::assertSame([self::DISCOVERY], self::client()->requested);
    }

    #[TestDox('one trailing slash is not a different issuer')]
    public function testDiscoveryToleratesATrailingSlash(): void
    {
        // Providers are not consistent about publishing the identifier with a
        // slash, and an application that copied it from the other spelling is
        // not misconfigured.
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers(self::ISSUER . '/'))]);
        self::announce();
        self::publish();

        self::assertSame('user-42', self::verify(self::token('remote')));
    }

    #[TestDox('a metadata document with no jwks_uri is refused')]
    public function testDiscoveryWithoutAnEndpoint(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::client()->publishesAt(self::DISCOVERY, json_encode(['issuer' => self::ISSUER], \JSON_THROW_ON_ERROR));

        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertStringContainsString('states no "jwks_uri"', $cause->getMessage());
    }

    #[TestDox('a metadata document pointing at a plaintext endpoint is refused')]
    public function testDiscoveredEndpointMustBeHttps(): void
    {
        // The one https check configuration cannot make in advance: this URL
        // is the issuer's to choose, and it arrives after the container is
        // built.
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::announce(jwksUri: 'http://idp.test/.well-known/jwks.json');

        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertStringContainsString('not https', $cause->getMessage());
    }

    #[TestDox('an oversized metadata document is refused before it is parsed')]
    public function testDiscoveryBodyCeiling(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers() + ['max_body_bytes' => 32])]);
        self::announce();

        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertStringContainsString('exceeds the 32-byte limit', $cause->getMessage());
    }

    #[TestDox('an unreachable metadata endpoint does not stop tokens signed with local keys (K6)')]
    public function testDiscoveryOutageLeavesLocalKeysAlone(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers(), consumerKeys: ['local'], keys: [
            'local' => ['pem_public' => self::keypair('local')['public'], 'algorithm' => 'RS256', 'kid' => 'local-2026'],
        ])]);
        self::client()->goesOffline();

        // The extra hop must not cost K6 anything: a discovery failure is the
        // same JwksResolutionException a jwks_uri failure is, which is what
        // lets the composite fall through to the keys already held here.
        self::assertSame('user-42', self::verify(self::token('local')));
    }

    #[TestDox('naming both a jwks_uri and a discovery issuer fails at container build')]
    public function testUriAndDiscoveryTogether(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/names both a jwks_uri and a discovery issuer/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['discovery' => self::ISSUER])]);
    }

    #[TestDox('naming neither a jwks_uri nor a discovery issuer fails at container build')]
    public function testNeitherUriNorDiscovery(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/names neither a jwks_uri nor a discovery issuer/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['uri' => null])]);
    }

    #[DataProvider('uris')]
    #[TestDox('a discovery issuer that is not https fails at container build: $_dataName')]
    public function testNonHttpsDiscoveryIsRefused(string $uri): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/names whatever keys they like/');

        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers($uri))]);
    }

    #[TestDox('an environment-backed discovery issuer is not judged at build either')]
    public function testEnvironmentDiscoveryIsNotJudgedAtBuild(): void
    {
        putenv('JWT_TEST_DISCOVERY=' . self::ISSUER);

        try {
            self::bootKernel(['medzuch_jwt' => self::configuration(['uri' => null, 'discovery' => '%env(JWT_TEST_DISCOVERY)%'])]);
            self::announce();
            self::publish();

            self::assertSame('user-42', self::verify(self::token('remote')));
            self::assertSame([self::DISCOVERY, self::URI], self::client()->requested);
        } finally {
            putenv('JWT_TEST_DISCOVERY');
        }
    }

    #[TestDox('an environment-backed plaintext discovery issuer is refused when the resolver is built')]
    public function testEnvironmentDiscoveryIsStillHeldToHttps(): void
    {
        // Nothing to read at build, so the guard cannot judge it — and without
        // a fence in the constructor the metadata would be fetched over a
        // channel an attacker can rewrite. They would then echo the issuer this
        // application configured, passing §4.3, and name keys of their own.
        putenv('JWT_TEST_DISCOVERY=http://idp.test');

        try {
            self::bootKernel(['medzuch_jwt' => self::configuration(['uri' => null, 'discovery' => '%env(JWT_TEST_DISCOVERY)%'])]);

            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessageMatches('/Discovery issuer must be an https:\/\/ URL/');

            self::getContainer()->get('medzuch_jwt.handler.partner');
        } finally {
            putenv('JWT_TEST_DISCOVERY');
        }
    }

    #[TestDox('a jwks_uri that turns plaintext in the cache is refused as a resolution failure')]
    public function testPoisonedCacheEntryIsRefusedInTheVocabularyK6Understands(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::announce();
        self::publish();
        self::verify(self::token('remote'));

        // The stored endpoint rewritten under a resolver that has not asked yet.
        // JwksResolutionException, not the delegate's InvalidArgumentException:
        // only the first is what a CompositeResolver falls through on.
        $cache = self::cache();
        foreach (array_keys($cache->ttls) as $key) {
            if (str_starts_with($key, 'oidc_discovery_')) {
                $cache->set($key, 'http://attacker.test/jwks.json');
            }
        }

        $next = new DiscoveredJwksResolver(self::ISSUER, self::client(), self::client(), $cache, new SystemClock());

        $this->expectException(JwksResolutionException::class);
        $this->expectExceptionMessageMatches('/reached a jwks_uri that is not https/');

        $next->resolve(['kid' => 'partner-2026']);
    }

    #[TestDox('a discovery endpoint that answers with an error is a resolution failure, not a crash')]
    public function testDiscoveryEndpointRefuses(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::client()->publishesAt(self::DISCOVERY, 'Service Unavailable', 503);

        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertStringContainsString('returned HTTP 503', $cause->getMessage());
        self::assertSame([self::DISCOVERY], self::client()->requested, 'a document that never arrived names no endpoint to ask');
    }

    #[TestDox('a document that is not JSON is a resolution failure, not a crash')]
    public function testDiscoveryDocumentIsNotJson(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers())]);
        self::client()->publishesAt(self::DISCOVERY, '<html>we moved</html>');

        $cause = self::refusalOf(self::token('remote'));

        self::assertInstanceOf(JwksResolutionException::class, $cause);
        self::assertStringContainsString('is not JSON', $cause->getMessage());
    }

    #[TestDox('an issuer identifier with a path is read at the OIDC spelling, not the RFC 8414 one')]
    public function testPathBearingIssuer(): void
    {
        // Keycloak and Azure AD publish under identifier + /.well-known/…;
        // RFC 8414 would insert the suffix before the path instead. Whichever
        // this bundle chose, the choice is worth pinning: the two disagree on
        // exactly the issuers that have a realm in them.
        $issuer = self::ISSUER . '/realms/app';

        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers($issuer))]);
        self::client()->publishesAt($issuer . '/.well-known/openid-configuration', json_encode([
            'issuer' => $issuer,
            'jwks_uri' => self::URI,
        ], \JSON_THROW_ON_ERROR));
        self::publish();

        self::assertSame('user-42', self::verify(self::token('remote')));
        self::assertSame([$issuer . '/.well-known/openid-configuration', self::URI], self::client()->requested);
    }

    #[DataProvider('blanks')]
    #[TestDox('a blank $_dataName fails at container build')]
    public function testBlankSourceIsRefused(string $option, string $value): void
    {
        // The check that moved out of the tree so `%env(...)%` could survive it.
        // Without a test of its own, a later tidy of the guard could drop the
        // branch and only the env tests above would still be watching.
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/has a blank ' . $option . '; omit it instead/');

        self::bootKernel(['medzuch_jwt' => self::configuration('uri' === $option
            ? ['uri' => $value]
            : ['uri' => null, 'discovery' => $value])]);
    }

    /** @return iterable<string, array{string, string}> */
    public static function blanks(): iterable
    {
        yield 'uri' => ['uri', ''];
        yield 'uri that is only spaces' => ['uri', '   '];
        yield 'discovery' => ['discovery', ''];
        yield 'discovery that is only spaces' => ['discovery', '   '];
    }

    #[TestDox('a document this bundle publishes is one this bundle accepts (K7 meets K8)')]
    public function testTheTwoHalvesOfDiscoveryAgree(): void
    {
        // The pair is only worth having if it closes: K8 writes the document
        // and K7 reads it, and every rule the reader enforces — the issuer
        // echo, https on the endpoint — is one the publisher has to satisfy.
        // Two suites each testing their own side would agree with themselves
        // and could still disagree with each other.
        self::bootKernel(['medzuch_jwt' => self::configuration(self::discovers()) + [
            'metadata' => [
                'issuer' => self::ISSUER,
                'jwks_uri' => self::URI,
                'extra' => ['response_types_supported' => ['code']],
            ],
        ]]);

        $published = self::getContainer()->get('medzuch_jwt.metadata_controller');
        self::assertInstanceOf(MetadataController::class, $published);

        // Served the way a reader would fetch it, then handed to the reader.
        self::client()->publishesAt(self::DISCOVERY, (string) $published(Request::create(self::DISCOVERY))->getContent());
        self::publish();

        self::assertSame('user-42', self::verify(self::token('remote')));
        self::assertSame([self::DISCOVERY, self::URI], self::client()->requested);
    }

    /** What actually refused the token, under the credential error every failure wears. */
    private static function refusalOf(string $token): ?\Throwable
    {
        try {
            self::verify($token);
            self::fail('the token should not have resolved');
        } catch (BadCredentialsException $refused) {
            return $refused->getPrevious();
        }
    }

    /**
     * Verifies a token that cannot resolve, N times, reporting how many
     * requests the issuer had seen after each attempt.
     *
     * @return list<int>
     */
    private static function attempts(string $token, int $times): array
    {
        $counts = [];

        for ($attempt = 0; $attempt < $times; ++$attempt) {
            try {
                self::verify($token);
                self::fail('a kid the issuer never published should not resolve');
            } catch (BadCredentialsException) {
                $counts[] = count(self::client()->requested);
            }
        }

        return $counts;
    }

    private static function verify(string $token): string
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.partner');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler->getUserBadgeFrom($token)->getUserIdentifier();
    }

    /**
     * A set addressed by issuer identifier rather than by endpoint.
     *
     * `uri` is nulled rather than omitted because {@see configuration()}
     * supplies it as the default and strips nulls: the two are alternatives,
     * and a set carrying both is a build failure of its own.
     *
     * @return array<string, mixed>
     */
    private static function discovers(string $issuer = self::ISSUER): array
    {
        return ['uri' => null, 'discovery' => $issuer];
    }

    /**
     * What the issuer says about itself at the well-known path.
     *
     * Only the two members this bundle reads; a real document carries dozens,
     * and a test naming them all would be asserting the provider's taste.
     */
    private static function announce(string $issuer = self::ISSUER, string $jwksUri = self::URI): void
    {
        self::client()->publishesAt(self::DISCOVERY, json_encode([
            'issuer' => $issuer,
            'jwks_uri' => $jwksUri,
        ], \JSON_THROW_ON_ERROR));
    }

    /**
     * Publishes the half of the remote keypair the issuer would publish. The
     * private half stays in the configuration below, which is what stands in
     * for the identity provider signing.
     */
    private static function publish(): void
    {
        $jwk = RsaPrivateKey::fromPem(self::keypair('remote')['private'], 'RS256', 'partner-2026')->toPublicKey()->toJwk();

        self::client()->publishes(json_encode(['keys' => [$jwk]], \JSON_THROW_ON_ERROR));
    }

    /** Mints through the bundle's own issuer, so the token is one it would produce. */
    private static function token(string $issuer): string
    {
        $minting = self::getContainer()->get('medzuch_jwt.issuer.' . $issuer);
        self::assertInstanceOf(AccessTokenIssuer::class, $minting);

        return $minting->issue('user-42')->value;
    }

    private static function clock(): FrozenClock
    {
        $clock = self::getContainer()->get('test.frozen_clock');
        self::assertInstanceOf(FrozenClock::class, $clock);

        return $clock;
    }

    private static function client(): StubHttpClient
    {
        $client = self::getContainer()->get('test.http_client');
        self::assertInstanceOf(StubHttpClient::class, $client);

        return $client;
    }

    private static function pool(): ArrayAdapter
    {
        $pool = self::getContainer()->get('test.cache_pool');
        self::assertInstanceOf(ArrayAdapter::class, $pool);

        return $pool;
    }

    private static function cache(): ArrayCache
    {
        $cache = self::getContainer()->get('test.cache');
        self::assertInstanceOf(ArrayCache::class, $cache);

        return $cache;
    }

    /**
     * @param array<string, mixed>                $set
     * @param list<string>                        $consumerKeys
     * @param array<string, array<string, mixed>> $keys
     * @param list<string>                        $algorithms
     * @param array<string, mixed>                $consumer overrides for the consumer entry
     *
     * @return array<string, mixed>
     */
    private static function configuration(array $set = [], array $consumerKeys = [], array $keys = [], array $algorithms = ['RS256'], array $consumer = []): array
    {
        // Both sides in one container: the signing halves stand in for the
        // identity provider, and only the public half of the remote one ever
        // reaches the consumer — through the endpoint, as it would in life.
        $signing = [
            'signing_remote' => ['pem_private' => self::keypair('remote')['private'], 'algorithm' => 'RS256', 'kid' => 'partner-2026'],
            'signing_local' => ['pem_private' => self::keypair('local')['private'], 'algorithm' => 'RS256', 'kid' => 'local-2026'],
        ];

        $issuer = static fn(string $key): array => [
            'issuer' => 'https://idp.test',
            'key' => $key,
            'client_id' => 'test-client',
            'audience' => 'https://api.test',
        ];

        return [
            'keys' => $keys + $signing,
            'issuers' => [
                'remote' => $issuer('signing_remote'),
                'local' => $issuer('signing_local'),
            ],
            'remote_jwks' => [
                'partner_idp' => array_filter($set + [
                    'uri' => self::URI,
                    'http_client' => 'test.http_client',
                    'cache' => 'test.cache',
                ], static fn(mixed $value): bool => null !== $value),
            ],
            'consumers' => [
                'partner' => $consumer + [
                    'issuer' => 'https://idp.test',
                    'audience' => 'https://api.test',
                    'keys' => $consumerKeys,
                    'remote_jwks' => 'partner_idp',
                    'allowed_algorithms' => $algorithms,
                ],
            ],
        ];
    }
}
