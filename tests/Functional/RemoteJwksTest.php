<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\MedzuchJwtBundle;
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

    /**
     * @param array<array-key, mixed> $options
     */
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
