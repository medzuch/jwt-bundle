<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Test\AssertsBearerChallenges;
use Medzuch\JwtBundle\Test\TestTokenFactory;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
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
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration());
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
        // pass it. This reads what was actually written.
        self::createClient();

        $now = time();

        $expired = self::payload(self::tokens()->expired());
        self::assertIsInt($expired['exp'] ?? null);
        self::assertLessThan($now, $expired['exp']);

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

    #[TestDox('scopes and claims the caller asks for reach the token')]
    public function testScopesAndClaimsAreCarried(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/scoped', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::tokens()->token('alice', scopes: ['reports.read']),
        ]);

        self::assertResponseIsSuccessful();
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

    private static function tokens(): TestTokenFactory
    {
        return TestTokenFactory::hmac(self::ISSUER, self::AUDIENCE, self::SECRET);
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
     * @return array<string, mixed>
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
