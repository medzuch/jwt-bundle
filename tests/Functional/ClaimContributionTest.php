<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use LogicException;
use Medzuch\JwtBundle\Event\JwtIssuedEvent;
use Medzuch\JwtBundle\Event\JwtIssuingEvent;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Issuer\IssuedToken;
use Medzuch\JwtBundle\Issuer\TokenIssuance;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsIssuance;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use Medzuch\JwtBundle\Tests\Functional\App\TenantClaims;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * What an application contributes to a token it mints, and what it is told
 * about one it has minted.
 *
 * The consumer here reads `tenant` — the custom mode's factory refuses a token
 * without one — so a contributed claim is asserted by the identity it produces
 * at the far end of a round trip rather than by reading the payload back. A
 * claim that survives signing, verification and a user factory is a claim that
 * is really in the token.
 */
#[CoversClass(AccessTokenIssuer::class)]
#[CoversClass(TokenIssuance::class)]
#[CoversClass(JwtIssuingEvent::class)]
#[CoversClass(JwtIssuedEvent::class)]
final class ClaimContributionTest extends WebTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration(), issuanceHooks: true);
    }

    #[TestDox('a claim a provider contributes reaches the consumer that reads it')]
    public function testProviderClaimReachesTheConsumer(): void
    {
        $client = self::browser();

        // Nothing at the call site names a tenant; the factory builds the
        // identifier out of `sub` and `tenant` all the same.
        self::assertSame('acme', self::tenantOf($client, self::issuer()->issue('user-7')));
    }

    #[TestDox('providers run in tag priority order, and the one that runs later wins')]
    public function testPriorityDecidesTheWinner(): void
    {
        $client = self::browser();

        self::assertSame('acme', self::tenantOf($client, self::issuer()->issue('user-7')));

        // Priority 10, so it ran first — and was overridden by the provider
        // that ran after it, the way a later event listener overrides an
        // earlier one.
        self::assertInstanceOf(TokenIssuance::class, self::provider('test.claims.first')->seen);
    }

    #[TestDox('a provider is told what is being minted, including the id the token will carry')]
    public function testIssuanceDescribesTheToken(): void
    {
        self::browser();

        $token = self::issuer()->issue('user-7', scopes: ['reports.read'], ttl: 120);

        $seen = self::provider('test.claims.tenant')->seen;

        self::assertInstanceOf(TokenIssuance::class, $seen);
        self::assertSame('default', $seen->issuerName);
        self::assertSame('user-7', $seen->subject);
        self::assertSame(['reports.read'], $seen->scopes);
        self::assertSame(['https://api.test'], $seen->audience);
        self::assertSame(120, $seen->ttl);
        // The same id the caller gets back, so a hook can record a token it may
        // later be asked to revoke.
        self::assertSame($token->jti, $seen->jti);
    }

    #[TestDox('the caller overrides a provider, and a listener overrides the caller')]
    public function testTheLastWordIsTheListener(): void
    {
        $client = self::browser();

        self::assertSame('by-hand', self::tenantOf($client, self::issuer()->issue('user-7', claims: ['tenant' => 'by-hand'])));

        self::listener()->adjust = ['tenant' => 'by-listener'];

        self::assertSame('by-listener', self::tenantOf($client, self::issuer()->issue('user-7', claims: ['tenant' => 'by-hand'])));
        // And it was handed what it overrode.
        self::assertSame('by-hand', self::listener()->sawIssuing['tenant'] ?? null);
    }

    #[TestDox('a provider cannot rewrite the scope of every token')]
    public function testProviderCannotSetAReservedClaim(): void
    {
        self::browser();

        self::provider('test.claims.tenant')->extra = ['scope' => 'admin'];

        $this->expectException(LogicException::class);
        // Named, because a container holds several providers and the message is
        // the only thing that says which one to go and fix.
        $this->expectExceptionMessage('Claim provider "' . TenantClaims::class . '" cannot set the reserved claim "scope"');

        self::issuer()->issue('user-7', scopes: ['reports.read']);
    }

    #[TestDox('a listener cannot rewrite the subject either')]
    public function testListenerCannotSetAReservedClaim(): void
    {
        self::browser();

        self::listener()->adjust = ['sub' => 'someone-else'];

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('A listener on JwtIssuingEvent cannot set the reserved claim "sub"');

        self::issuer()->issue('user-7');
    }

    #[TestDox('the audit event carries the id and the claims, and never the token')]
    public function testIssuedEventIsAnAuditRecord(): void
    {
        self::browser();

        $token = self::issuer()->issue('user-7', scopes: ['reports.read']);

        $issued = self::listener()->issued;

        self::assertInstanceOf(JwtIssuedEvent::class, $issued);
        self::assertSame($token->jti, $issued->issuance->jti);
        self::assertSame(['reports.read'], $issued->issuance->scopes);
        self::assertSame('acme', $issued->claims['tenant'] ?? null);
        // The credential itself is deliberately absent: a listener logging what
        // it is handed cannot log a working token by accident.
        self::assertSame(['issuance', 'claims'], array_keys(get_object_vars($issued)));
    }

    #[TestDox('an issuer with nothing tagged and nothing listening mints a token without the claim')]
    public function testTheClaimComesFromTheProviderAndNowhereElse(): void
    {
        // The same configuration, hooks off: the tenant is contributed by the
        // provider rather than sitting in configuration, so this token has none
        // and the factory refuses it.
        $plain = new SecuredKernel(self::configuration());
        $plain->boot();
        $issuer = $plain->getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);
        $token = $issuer->issue('user-7');
        $plain->shutdown();

        $client = self::browser();
        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);

        self::assertResponseStatusCodeSame(401);
    }

    /**
     * A client that keeps its kernel between requests.
     *
     * `KernelBrowser` reboots from the second request onwards, which builds a
     * new container and with it new providers and a new listener — so what a
     * test set on one and what it reads back from another would be two
     * different objects, and the assertion would be about nothing.
     */
    private static function browser(): KernelBrowser
    {
        $client = self::createClient();
        $client->disableReboot();

        return $client;
    }

    /**
     * The tenant half of the identity the custom factory built, which is the
     * contributed claim having made it all the way through.
     */
    private static function tenantOf(KernelBrowser $client, IssuedToken $token): string
    {
        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);
        self::assertResponseIsSuccessful();

        $body = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($body);

        $user = $body['user'] ?? null;
        self::assertIsString($user);
        self::assertStringContainsString('@', $user);

        return substr($user, (int) strpos($user, '@') + 1);
    }

    private static function provider(string $id): TenantClaims
    {
        $provider = self::getContainer()->get($id);
        self::assertInstanceOf(TenantClaims::class, $provider);

        return $provider;
    }

    private static function listener(): RecordsIssuance
    {
        $listener = self::getContainer()->get('test.issuance_listener');
        self::assertInstanceOf(RecordsIssuance::class, $listener);

        return $listener;
    }

    private static function issuer(): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    /**
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => [
                'issuer' => 'https://issuer.test',
                'key' => 'default',
                'client_id' => 'test-client',
                'audience' => 'https://api.test',
            ]],
            'consumers' => ['api' => [
                'issuer' => 'https://issuer.test',
                'audience' => 'https://api.test',
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
                'user' => ['mode' => 'custom', 'factory' => 'test.user_factory'],
            ]],
        ];
    }
}
