<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\Dir;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Test\AssertsBearerChallenges;
use Medzuch\JwtBundle\Test\TestTokenFactory;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\ExpectationFailedException;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The helpers this bundle ships, used the way an application would use them.
 *
 * Which is the only honest test for them: they exist so that somebody else's
 * functional suite can mint a token their firewall must refuse and then say
 * what the refusal should have carried. So this case is that suite — a real
 * kernel, a real firewall, and nothing of the bundle's own test furniture.
 */
#[CoversClass(TestTokenFactory::class)]
#[CoversClass(AssertsBearerChallenges::class)]
final class TestHelpersTest extends WebTestCase
{
    use AssertsBearerChallenges;
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';

    /** Exactly the 32 bytes A256KW is. */
    private const SEALING = '0123456789abcdef0123456789abcdef';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new SecuredKernel(is_array($config) ? $config : []);
    }

    #[TestDox('a token the factory mints is one the firewall accepts')]
    public function testMintedTokenIsAccepted(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/whoami', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::tokens()->token('alice'),
        ]);

        self::assertResponseIsSuccessful();
        self::assertSame('alice', self::json($client)['user'] ?? null);
    }

    /**
     * @param callable(TestTokenFactory): string $mint
     */
    #[DataProvider('refusals')]
    #[TestDox('a token that is $defect is refused')]
    public function testTokensAFirewallMustRefuse(string $defect, callable $mint): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $mint(self::tokens())]);

        self::assertResponseStatusCodeSame(401);
        self::assertInvalidToken($client->getResponse());
    }

    /**
     * @return iterable<string, array{string, callable(TestTokenFactory): string}>
     */
    public static function refusals(): iterable
    {
        yield 'expired' => ['past its expiry', static fn(TestTokenFactory $t): string => $t->expired()];
        yield 'not yet valid' => ['not valid yet', static fn(TestTokenFactory $t): string => $t->notYetValid()];
        yield 'audience' => ['addressed elsewhere', static fn(TestTokenFactory $t): string => $t->withAudience('https://other.test')->token()];
        yield 'issuer' => ['from another issuer', static fn(TestTokenFactory $t): string => $t->withIssuer('https://elsewhere.test')->token()];

        // A stranger is a second factory rather than a method: every algorithm
        // gets the same answer, and there is nothing to switch on.
        yield 'signature' => ['signed by a stranger', static fn(): string => TestTokenFactory::hmac(
            self::ISSUER,
            self::AUDIENCE,
            'a-different-secret-of-32-bytes-min!!!',
        )->token()];
    }

    #[TestDox('each refusal is minted the way it is named, not merely broken')]
    public function testEachDefectIsTheOneItClaims(): void
    {
        // The firewall answers 401 to all five above, so that test says the
        // tokens are refused without saying they are refused for the reason
        // asked for — an `expired()` that minted a not-yet-valid token would
        // pass it. This reads what was actually written, and boots nothing:
        // minting needs no container, which is half the point of the factory.
        $now = time();

        $expired = self::payload(self::tokens()->expired());
        self::assertIsInt($expired['exp'] ?? null);
        self::assertIsInt($expired['iat'] ?? null);
        self::assertLessThan($now, $expired['exp']);
        // Issued before it expired. Minted at "now" the token would carry an
        // `exp` an hour before its own `iat` — refused for being expired, and
        // also nonsense, which is not what this method's name promises.
        self::assertLessThan($expired['exp'], $expired['iat']);

        $early = self::payload(self::tokens()->notYetValid());
        self::assertIsInt($early['nbf'] ?? null);
        self::assertGreaterThan($now, $early['nbf']);
        self::assertGreaterThan($early['nbf'], $early['exp'] ?? 0);

        $elsewhere = self::payload(self::tokens()->withIssuer('https://elsewhere.test')->token());
        self::assertSame('https://elsewhere.test', $elsewhere['iss'] ?? null);

        $others = self::payload(self::tokens()->withAudience(['https://a.test', 'https://b.test'])->token());
        self::assertSame(['https://a.test', 'https://b.test'], $others['aud'] ?? null);

        // And the ordinary one: alive, named, and carrying the `jti` RFC 9068
        // §2.2 requires whether or not the caller asked for one.
        $valid = self::payload(self::tokens()->withTtl(60)->token('alice', ['reports.read'], ['tenant' => 'acme'], 'known-id'));
        self::assertSame('alice', $valid['sub'] ?? null);
        self::assertSame('reports.read', $valid['scope'] ?? null);
        self::assertSame('acme', $valid['tenant'] ?? null);
        self::assertSame('known-id', $valid['jti'] ?? null);
        self::assertSame('test-client', $valid['client_id'] ?? null);

        $expiry = $valid['exp'] ?? null;
        $issued = $valid['iat'] ?? null;
        self::assertIsInt($expiry);
        self::assertIsInt($issued);
        self::assertSame(60, $expiry - $issued);
    }

    #[TestDox('a request with no token is challenged, and the challenge names no error')]
    public function testChallengeToARequestWithNoToken(): void
    {
        $client = self::createClient();
        $client->request('GET', '/api/whoami');

        self::assertResponseStatusCodeSame(401);
        self::assertBearerChallenge($client->getResponse(), realm: 'reports-api');
    }

    #[TestDox('a scope denial names the scope, and a role denial names nothing')]
    public function testWhatARefusalCarries(): void
    {
        $client = self::createClient();
        $token = self::tokens()->token('alice', scopes: ['nothing.useful']);

        $client->request('GET', '/api/scoped', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertResponseStatusCodeSame(403);
        self::assertInsufficientScope($client->getResponse(), 'reports.read');

        $client->request('GET', '/api/role', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertResponseStatusCodeSame(403);
        self::assertNoBearerChallenge($client->getResponse());
    }

    #[TestDox('the scopes the caller asks for become the roles the application sees')]
    public function testScopesTravelAllTheWay(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/scoped', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::tokens()->token('alice', scopes: ['reports.read']),
        ]);

        self::assertResponseIsSuccessful();
        // Not just "the rule let it through": this consumer maps the `scope`
        // claim to roles, so the controller seeing ROLE_reports.read is the
        // scope having survived minting, verification and mapping.
        $roles = self::json($client)['roles'] ?? null;
        self::assertIsArray($roles);
        self::assertContains('ROLE_reports.read', $roles);
    }

    #[TestDox('the asymmetric half signs with the key an issuer would use')]
    public function testSignedWithAPrivateKey(): void
    {
        $pair = self::keypair('helpers-rsa');

        $client = self::createClient(['medzuch_jwt' => self::rsaConfiguration($pair['public'])]);

        $tokens = TestTokenFactory::signedWith(
            self::ISSUER,
            self::AUDIENCE,
            new Rs256(),
            RsaPrivateKey::fromPem($pair['private'], 'RS256'),
        );

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokens->token('alice')]);
        self::assertResponseIsSuccessful();

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokens->expired()]);
        self::assertResponseStatusCodeSame(401);
    }

    #[TestDox('the client id and the key id are the factory\'s to set')]
    public function testClientIdAndKeyIdAreCarried(): void
    {
        // Its own secret: HS384 wants 48 bytes (RFC 8725 §3.5), and the
        // factory hands the length rule to the library rather than papering
        // over it.
        $token = TestTokenFactory::hmac(self::ISSUER, self::AUDIENCE, str_repeat('a-48-byte-secret', 3), 'HS384', 'signing-2026')
            ->withClientId('another-client')
            ->token('alice');

        self::assertSame('another-client', self::payload($token)['client_id'] ?? null);

        // The `kid` belongs to the key, so it rides in the header rather than
        // the claims — which is where a consumer resolving by one looks.
        $header = self::header($token);
        self::assertSame('signing-2026', $header['kid'] ?? null);
        self::assertSame('HS384', $header['alg'] ?? null);
    }

    #[TestDox('a frozen clock is the only thing between a live token and an expired one')]
    public function testTimeTravel(): void
    {
        // The README's four lines of YAML, as a test: one frozen clock reaches
        // the consumer, and the factory is handed the same one so that `iat`
        // is not minted by a clock the consumer never agreed with.
        $client = self::createClient(['medzuch_jwt' => self::configuration() + ['clock' => 'test.frozen_clock']]);
        // Without this the kernel is rebuilt before the second request and the
        // clock goes back to where it was frozen, taking the tick with it.
        $client->disableReboot();

        $clock = self::getContainer()->get('test.frozen_clock');
        self::assertInstanceOf(FrozenClock::class, $clock);

        $token = self::tokens()->withClock($clock)->withTtl(600)->token('alice');

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);
        self::assertResponseIsSuccessful();

        // Nothing slept: the same request, the same token, one clock moved.
        $clock->tick(new DateInterval('PT2H'));

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);
        self::assertResponseStatusCodeSame(401);
    }

    /**
     * @return array<string, mixed>
     */
    private static function payload(string $token): array
    {
        $segments = explode('.', $token);
        self::assertCount(3, $segments);

        $json = base64_decode(strtr($segments[1], '-_', '+/'), true);
        self::assertIsString($json);

        $claims = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($claims);

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    #[TestDox('the assertions fail when the header says something else')]
    public function testTheAssertionsCanFail(): void
    {
        // An assertion helper that always passes is worse than none, and this
        // suite uses these helpers to check the rest of the bundle — so what
        // they refuse has to be asserted, not assumed.
        $challenged = new Response('', 401, ['WWW-Authenticate' => 'Bearer realm="api"']);
        $refused = new Response('', 403, ['WWW-Authenticate' => 'Bearer realm="api", error="insufficient_scope", scope="reports.read"']);
        $bare = new Response('', 403);

        self::assertFails(static fn() => self::assertBearerChallenge($challenged, realm: 'another'));
        self::assertFails(static fn() => self::assertBearerChallenge($refused));
        self::assertFails(static fn() => self::assertInvalidToken($refused));
        self::assertFails(static fn() => self::assertInsufficientScope($challenged));
        self::assertFails(static fn() => self::assertInsufficientScope($refused, 'reports.write'));
        self::assertFails(static fn() => self::assertNoBearerChallenge($refused));
        self::assertFails(static fn() => self::assertInvalidToken($bare));
    }

    #[TestDox('a challenge is read whatever its scheme is cased and however it is spaced')]
    public function testTheHeaderIsReadLeniently(): void
    {
        // RFC 9110 §11.6.1 makes the scheme case-insensitive, and Symfony's
        // own header is spaced differently from this bundle's. A test asserting
        // a fact about a refusal should not fail over either.
        self::assertInvalidToken(new Response('', 401, ['WWW-Authenticate' => 'bearer realm="api",error="invalid_token"']));
        self::assertInsufficientScope(
            new Response('', 403, ['WWW-Authenticate' => 'BEARER  ERROR="insufficient_scope",  Scope="reports.read reports.write"']),
            'reports.write',
        );
    }

    private static function assertFails(callable $assertion): void
    {
        try {
            $assertion();
        } catch (ExpectationFailedException) {
            return;
        }

        self::fail('this assertion should have failed');
    }

    /**
     * @return array<string, mixed>
     */
    private static function header(string $token): array
    {
        $segments = explode('.', $token);
        self::assertCount(3, $segments);

        $json = base64_decode(strtr($segments[0], '-_', '+/'), true);
        self::assertIsString($json);

        $header = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($header);

        /** @var array<string, mixed> $header */
        return $header;
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function rsaConfiguration(string $publicKey): array
    {
        $configuration = self::configuration();
        $configuration['keys'] = ['default' => ['pem_public' => $publicKey, 'algorithm' => 'RS256']];
        $configuration['consumers']['api']['allowed_algorithms'] = ['RS256'];

        return $configuration;
    }

    private static function tokens(): TestTokenFactory
    {
        return TestTokenFactory::hmac(self::ISSUER, self::AUDIENCE, self::SECRET);
    }

    /**
     * The half an application cannot write for itself: a firewall whose
     * consumer reads encrypted tokens has nothing to test with unless the
     * factory can seal one (C12).
     */
    #[TestDox('a sealed token the factory mints is one an encrypted firewall accepts')]
    public function testSealedTokenIsAccepted(): void
    {
        $client = self::createClient(['medzuch_jwt' => self::sealedConfiguration()]);

        $client->request('GET', '/api/whoami', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::sealedTokens()->token('alice'),
        ]);

        self::assertResponseIsSuccessful();
        self::assertSame('alice', self::json($client)['user'] ?? null);
    }

    #[TestDox('the refusals are sealed too, so the token inside is what gets judged')]
    public function testSealedRefusalIsStillARefusal(): void
    {
        $client = self::createClient(['medzuch_jwt' => self::sealedConfiguration()]);

        $expired = self::sealedTokens()->expired('alice');

        // Five segments: the refusal travelled inside a JWE the consumer had
        // to open first, rather than arriving as a bare signed token the
        // consumer would have refused for being unencrypted.
        self::assertCount(5, explode('.', $expired));

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $expired]);

        self::assertResponseStatusCodeSame(401);
        self::assertInvalidToken($client->getResponse());
    }

    /**
     * The `dir` case, and the one that pins the outer `kid`: a direct
     * recipient is found by its key id and by nothing else, so a factory that
     * did not write one would mint a token no consumer could open.
     */
    #[TestDox('a directly encrypted token from the factory names the key it was sealed to')]
    public function testDirectlyEncryptedTokenIsAccepted(): void
    {
        $configuration = self::configuration();
        $configuration['jwe_keys'] = ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256GCM', 'kid' => 'enc-2026']];
        $configuration['consumers']['api']['jwe'] = [
            'keys' => ['sealed'],
            'allowed_key_management' => ['dir'],
            'allowed_content_encryption' => ['A256GCM'],
        ];

        $client = self::createClient(['medzuch_jwt' => $configuration]);

        $token = self::tokens()->encryptedWith(
            new Dir(),
            new A256Gcm(),
            OctKey::fromBinary(self::SEALING, 'A256GCM', 'enc-2026'),
        )->token('alice');

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertResponseIsSuccessful();
        self::assertSame('alice', self::json($client)['user'] ?? null);
    }

    private static function sealedTokens(): TestTokenFactory
    {
        return self::tokens()->encryptedWith(
            new A256Kw(),
            new A256Gcm(),
            OctKey::fromBinary(self::SEALING, 'A256KW', 'enc-2026'),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function sealedConfiguration(): array
    {
        $configuration = self::configuration();
        $configuration['jwe_keys'] = ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256KW', 'kid' => 'enc-2026']];
        $configuration['consumers']['api']['jwe'] = [
            'keys' => ['sealed'],
            'allowed_key_management' => ['A256KW'],
            'allowed_content_encryption' => ['A256GCM'],
        ];

        return $configuration;
    }

    /**
     * @return array<string, mixed>
     */
    private static function json(KernelBrowser $client): array
    {
        $body = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($body);

        /** @var array<string, mixed> $body */
        return $body;
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function configuration(): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => [
                'issuer' => self::ISSUER,
                'audience' => self::AUDIENCE,
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
                'realm' => 'reports-api',
                'user' => ['mode' => 'claims', 'roles' => ['claim' => 'scope']],
            ]],
        ];
    }
}
