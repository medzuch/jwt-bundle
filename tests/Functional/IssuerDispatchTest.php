<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\NestedJwtBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\JwtBundle\Security\IssuerDispatchingHandler;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Test\TestTokenFactory;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsVerification;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use UnexpectedValueException;

/**
 * One firewall in front of several tenants, the token saying which (C11).
 *
 * Two claims run through the file. The first is that the routing works and
 * routes by the only thing it may: a token is judged by the consumer expecting
 * the issuer it names, and by no other. The second is the one the design rests
 * on — that reading an unverified `iss` gives nothing away, because the
 * consumer it selects then asks every question it would have asked anyway. A
 * token from tenant A relabelled to reach tenant B's consumer is refused by
 * that consumer, on tenant B's keys.
 */
#[CoversClass(IssuerDispatchingHandler::class)]
final class IssuerDispatchTest extends WebTestCase
{
    use RestoresExceptionHandler;

    /** @var list<string> environment variables a case set, and this has to unset */
    private static array $environment = [];

    private const A = 'https://a.tenants.test';
    private const B = 'https://b.tenants.test';
    private const AUDIENCE = 'https://api.test';

    private const SECRET_A = 'tenant-a-secret-of-at-least-32-bytes';
    private const SECRET_B = 'tenant-b-secret-of-at-least-32-bytes';

    /** Exactly 32 bytes, so it is what A256KW is made of. */
    private const SEALING = '0123456789abcdef0123456789abcdef';

    protected function tearDown(): void
    {
        foreach (self::$environment as $name) {
            unset($_ENV[$name]);
            putenv($name);
        }

        self::$environment = [];

        parent::tearDown();

        // Called by hand: this `tearDown()` overrides the trait's, silently,
        // and without it the handler FrameworkBundle installs stays up — which
        // the current Symfony does not report and the 6.4 floor does.
        $this->restoreExceptionHandler();
    }

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();
        $config = is_array($config) ? $config : [];

        return ($options['firewall'] ?? false) === true ? new SecuredKernel($config) : new TestKernel($config);
    }

    #[TestDox('each tenant\'s token authenticates through the one firewall')]
    public function testBothTenantsAuthenticate(): void
    {
        $client = self::createClient(['firewall' => true]);

        foreach ([self::A => self::SECRET_A, self::B => self::SECRET_B] as $issuer => $secret) {
            $client->request('GET', '/api/whoami', server: [
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::tokenFrom($issuer, $secret),
            ]);

            self::assertResponseIsSuccessful();
            self::assertSame('alice', self::json($client)['user'] ?? null);
        }
    }

    /**
     * The claim the whole design rests on. The unverified `iss` chooses the
     * judge and nothing else: a token minted with tenant A's key, relabelled
     * to reach tenant B's consumer, is refused there for the signature it
     * carries.
     */
    #[TestDox('claiming to be another tenant only buys that tenant\'s keys')]
    public function testRoutingGrantsNothing(): void
    {
        self::bootKernel();

        // Tenant A's secret, tenant B's name on it: the dispatcher hands it to
        // B's consumer, which holds B's key and refuses it.
        self::assertSame(
            RejectionReason::SignatureInvalid,
            self::refusal(self::tokenFrom(self::B, self::SECRET_A)),
        );
    }

    #[TestDox('the consumer that judged it is the one that announces it')]
    public function testTheVerdictBelongsToTheTenant(): void
    {
        self::bootKernel();

        self::dispatcher()->getUserBadgeFrom(self::tokenFrom(self::B, self::SECRET_B));

        $verified = self::listener()->verified;
        self::assertCount(1, $verified);
        self::assertSame('tenant_b', $verified[0]->consumer);
        self::assertSame(self::B, $verified[0]->claims->issuer());
    }

    #[TestDox('an issuer no consumer expects is refused before a key is fetched')]
    public function testUnknownIssuer(): void
    {
        self::bootKernel();

        self::assertSame(
            RejectionReason::WrongIssuer,
            self::refusal(self::tokenFrom('https://c.tenants.test', self::SECRET_A)),
        );
    }

    /**
     * Announced under the dispatcher's own name: a token that routes nowhere
     * never reaches a consumer, and a refusal nothing announces is one nobody
     * can count.
     */
    #[TestDox('a token that routes nowhere is still announced, by the dispatcher')]
    public function testARefusalWithNoConsumerIsStillAnnounced(): void
    {
        self::bootKernel();

        self::refusal(self::tokenFrom('https://c.tenants.test', self::SECRET_A));

        $rejected = self::listener()->rejected;
        self::assertCount(1, $rejected);
        self::assertSame('api', $rejected[0]->consumer);
        self::assertSame(RejectionReason::WrongIssuer, $rejected[0]->reason);
    }

    #[TestDox('a token naming no issuer at all is refused the same way')]
    public function testNoIssuer(): void
    {
        self::bootKernel();

        self::assertSame(RejectionReason::WrongIssuer, self::refusal(self::unsigned()));
    }

    /**
     * `malformed`, not `wrong_issuer`: a broken bearer string is the answer a
     * consumer named directly would have given, and a client shipping them is
     * a different thing to chase than a tenant nobody configured. The
     * dispatcher keeps the two apart rather than folding both into its own
     * question.
     */
    #[TestDox('something that is not a token at all is malformed, not an unknown tenant')]
    public function testGarbage(): void
    {
        self::bootKernel();

        self::assertSame(RejectionReason::Malformed, self::refusal('not.a.jwt'));
    }

    /**
     * The reason the consumers arrive as a locator: a dispatcher in front of
     * twenty tenants must not open twenty denylists to answer one token. Read
     * off the container, which is the only place the claim is observable.
     */
    #[TestDox('only the consumer a token routed to is built')]
    public function testTheOtherTenantIsNeverBuilt(): void
    {
        self::bootKernel();

        $container = self::getContainer();

        self::dispatcher()->getUserBadgeFrom(self::tokenFrom(self::B, self::SECRET_B));

        self::assertTrue($container->initialized('medzuch_jwt.handler.tenant_b'));
        self::assertFalse($container->initialized('medzuch_jwt.handler.tenant_a'));
    }

    /**
     * An issuer that resolves to nothing — an environment variable nobody set
     * — is a route no token could mean and one an empty `iss` would land on.
     * Visible in the same place the ambiguity is, and refused there.
     */
    #[TestDox('a consumer whose issuer is empty is refused when the dispatcher is built')]
    public function testAnEmptyIssuer(): void
    {
        self::withEnvironment(['TENANT_B_ISSUER' => '']);

        self::bootKernel(['medzuch_jwt' => self::configuration(issuerOfB: '%env(TENANT_B_ISSUER)%')]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/routes to consumer "tenant_b", whose issuer is empty/');

        self::dispatcher();
    }

    /**
     * One tenant sending encrypted tokens and another sending signed ones is
     * an ordinary migration, and the order `issuerOf()` reads in is what makes
     * it work: three segments are tried first, five only if that fails.
     */
    #[TestDox('a signed tenant and an encrypted tenant sit behind one dispatcher')]
    public function testMixedTenants(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(sealedTenant: 'tenant_b')]);

        self::assertSame('alice', self::dispatcher()->getUserBadgeFrom(self::tokenFrom(self::A, self::SECRET_A))->getUserIdentifier());
        self::assertSame('tenant_a', self::listener()->verified[0]->consumer);

        $sealed = self::sealed(self::tokenFrom(self::B, self::SECRET_B), ['iss' => self::B]);

        self::assertSame('alice', self::dispatcher()->getUserBadgeFrom($sealed)->getUserIdentifier());
        self::assertSame('tenant_b', self::listener()->verified[1]->consumer);

        // And neither is offered to the other: a signed token naming the
        // encrypted tenant is refused for having no envelope, not accepted for
        // looking like the token the other tenant sends.
        self::assertSame(RejectionReason::Malformed, self::refusal(self::tokenFrom(self::B, self::SECRET_B)));
    }

    /**
     * An encrypted token has nothing to read without a key, so it routes on
     * the `iss` its sender replicated into the outer header (RFC 7519 §5.3) —
     * which is the case that section exists for. The consumer it lands on
     * decrypts and holds the copy to the claim inside.
     */
    #[TestDox('an encrypted token routes on the issuer replicated in its outer header')]
    public function testEncryptedTokenRoutesOnTheOuterHeader(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(sealed: true)]);

        $sealed = self::sealed(self::tokenFrom(self::B, self::SECRET_B), ['iss' => self::B]);

        self::assertSame('alice', self::dispatcher()->getUserBadgeFrom($sealed)->getUserIdentifier());
        self::assertSame('tenant_b', self::listener()->verified[0]->consumer ?? null);
    }

    #[TestDox('an encrypted token replicating nothing has no issuer to route on')]
    public function testEncryptedTokenWithoutAReplicatedIssuer(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(sealed: true)]);

        self::assertSame(
            RejectionReason::WrongIssuer,
            self::refusal(self::sealed(self::tokenFrom(self::B, self::SECRET_B), [])),
        );
    }

    /**
     * The outer header is not a way past the consumer either, and the refusal
     * it earns says something worth recording: labelling tenant A's token as
     * B's routes it to B's consumer, which refuses it on B's key before the
     * §5.3 comparison is ever reached.
     *
     * Which is why that comparison cannot fail behind a dispatcher at all: the
     * outer `iss` has to equal the route to arrive, the inner `iss` has to
     * equal the consumer's issuer to verify, and the route is that issuer. The
     * two checks converge on the same value — §5.3 is there for a receiver
     * that was handed the token directly, and this one still runs it.
     */
    #[TestDox('relabelling the envelope only routes to a consumer that refuses it')]
    public function testEncryptedTokenWithALyingOuterIssuer(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(sealed: true)]);

        self::assertSame(
            RejectionReason::UnknownKey,
            self::refusal(self::sealed(self::tokenFrom(self::A, self::SECRET_A), ['iss' => self::B], 'tenant_a')),
        );
    }

    /**
     * Through the firewall rather than through the handler: an unroutable
     * token is a 401 an application ships, not the 500 an exception escaping
     * the handler would be.
     */
    #[TestDox('a token no tenant expects is a 401 through the firewall, not an error')]
    public function testUnknownIssuerIsAnUnauthorizedResponse(): void
    {
        $client = self::createClient(['firewall' => true]);

        $client->request('GET', '/api/whoami', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::tokenFrom('https://c.tenants.test', self::SECRET_A),
        ]);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
        self::assertStringContainsString('Bearer', (string) $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    #[TestDox('a request with no token gets the dispatcher\'s own realm')]
    public function testTheChallengeNamesTheDispatcher(): void
    {
        $client = self::createClient(['firewall' => true]);

        $client->request('GET', '/api/whoami');

        self::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
        self::assertStringContainsString('realm="tenants"', (string) $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /**
     * Two consumers whose `issuer` is the same *string* are refused when the
     * container is built. Two different env references that resolve to one URL
     * cannot be seen there — this is that case, and the dispatcher asks it of
     * itself when it is constructed, which `jwt:config:check` is what runs.
     */
    #[TestDox('two tenants whose env vars resolve to one issuer are refused when the dispatcher is built')]
    public function testTwoTenantsOnOneIssuer(): void
    {
        self::withEnvironment(['TENANT_B_ISSUER' => self::A]);

        self::bootKernel(['medzuch_jwt' => self::configuration(issuerOfB: '%env(TENANT_B_ISSUER)%')]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageMatches('/cannot choose between consumers "tenant_a" and "tenant_b"/');

        self::dispatcher();
    }

    /**
     * An environment the kernel reads through `%env(...)%`, undone after the
     * case: the two mistakes only a resolved value shows are the two this
     * suite has to set one for.
     *
     * @param array<string, string> $variables
     */
    private static function withEnvironment(array $variables): void
    {
        foreach ($variables as $name => $value) {
            $_ENV[$name] = $value;
            putenv($name . '=' . $value);
        }

        self::$environment = array_keys($variables);
    }

    private static function tokenFrom(string $issuer, string $secret): string
    {
        return TestTokenFactory::hmac($issuer, self::AUDIENCE, $secret)->token('alice');
    }

    /**
     * A signed token with no `iss` at all, which the factory will not mint
     * because a consumer would refuse it — which is the point here.
     */
    private static function unsigned(): string
    {
        return (string) \Medzuch\Jwt\Jwt\JwtBuilder::create()
            ->subject('alice')
            ->signWith(new Hs256(), HmacKey::fromBinary(self::SECRET_A, 'HS256'))
            ->build();
    }

    /**
     * @param array<string, mixed> $outerHeader
     */
    private static function sealed(string $signed, array $outerHeader, string $tenant = 'tenant_b'): string
    {
        [$secret, $kid] = 'tenant_a' === $tenant
            ? [self::SEALING, 'enc-a']
            : [strrev(self::SEALING), 'enc-b'];

        return (string) NestedJwtBuilder::wrap(
            new CompactJws($signed),
            new A256Kw(),
            new A256Gcm(),
            OctKey::fromBinary($secret, 'A256KW', $kid, KeyUse::Enc),
            $outerHeader + ['kid' => $kid],
        );
    }

    private static function refusal(string $token): RejectionReason
    {
        try {
            self::dispatcher()->getUserBadgeFrom($token);
        } catch (RejectedTokenException $failure) {
            return $failure->reason;
        }

        self::fail('the token should have been refused');
    }

    private static function dispatcher(): AccessTokenHandlerInterface
    {
        $dispatcher = self::getContainer()->get('medzuch_jwt.dispatcher.api');
        self::assertInstanceOf(AccessTokenHandlerInterface::class, $dispatcher);

        return $dispatcher;
    }

    private static function listener(): RecordsVerification
    {
        $listener = self::getContainer()->get('test.verification_listener');
        self::assertInstanceOf(RecordsVerification::class, $listener);

        return $listener;
    }

    /**
     * @return array<string, mixed>
     */
    private static function json(KernelBrowser $client): array
    {
        $decoded = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param ?string $issuerOfB an issuer for the second tenant other than its
     *                           own, for the one ambiguity the container cannot see
     *
     * @return array<string, mixed>
     */
    private static function configuration(bool $sealed = false, ?string $issuerOfB = null, ?string $sealedTenant = null): array
    {
        // A key per tenant, not one between them: a tenant that could decrypt
        // another's envelope is not a tenant boundary, and it is what makes a
        // mis-routed encrypted token fail at the envelope rather than inside.
        $envelope = static fn(string $tenant): array => ['jwe' => [
            'keys' => [$tenant],
            'allowed_key_management' => ['A256KW'],
            'allowed_content_encryption' => ['A256GCM'],
        ]];

        $encrypts = static fn(string $tenant): bool => $sealed || $sealedTenant === $tenant;

        return [
            'keys' => [
                'tenant_a' => ['hmac' => self::SECRET_A],
                'tenant_b' => ['hmac' => self::SECRET_B],
            ],
            'jwe_keys' => [
                'tenant_a' => ['secret' => self::SEALING, 'algorithm' => 'A256KW', 'kid' => 'enc-a'],
                'tenant_b' => ['secret' => strrev(self::SEALING), 'algorithm' => 'A256KW', 'kid' => 'enc-b'],
            ],
            'consumers' => [
                'tenant_a' => ($encrypts('tenant_a') ? $envelope('tenant_a') : []) + [
                    'issuer' => self::A,
                    'audience' => self::AUDIENCE,
                    'keys' => ['tenant_a'],
                    'allowed_algorithms' => ['HS256'],
                ],
                'tenant_b' => ($encrypts('tenant_b') ? $envelope('tenant_b') : []) + [
                    'issuer' => $issuerOfB ?? self::B,
                    'audience' => self::AUDIENCE,
                    'keys' => ['tenant_b'],
                    'allowed_algorithms' => ['HS256'],
                ],
            ],
            'dispatchers' => [
                'api' => ['consumers' => ['tenant_a', 'tenant_b'], 'realm' => 'tenants'],
            ],
        ];
    }
}
