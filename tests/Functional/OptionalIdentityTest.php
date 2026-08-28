<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Endpoints that answer with or without a token (C15): a public page that shows
 * more to a caller who said who they are, and the same page for one who did not.
 *
 * The capability needs no code in this bundle, which is the finding worth
 * pinning. Symfony's `AccessTokenAuthenticator::supports()` returns `false` when
 * the extractor finds nothing, so an anonymous request is never a failed
 * authentication — it is no authentication at all, and what refuses it is the
 * access rule, not the firewall. Exempt the path from the rule and the same
 * firewall serves both callers.
 *
 * What that leaves is a promise with a sharp edge, and these are the rows that
 * hold it: a token which is present but bad is still a 401. "Optional" is about
 * a caller who did not answer, not about one who answered wrongly — a bearer
 * whose token has expired is told to refresh it rather than quietly served the
 * anonymous page and left to wonder why their name is gone.
 */
#[CoversClass(AccessTokenHandler::class)]
final class OptionalIdentityTest extends WebTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    /**
     * `$options` is ignored, as in {@see RoundTripTest}: every case wants the
     * same kernel, and SecuredKernel fixes the environment and debug flags.
     *
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration());
    }

    #[TestDox('a caller with no token reaches the endpoint as nobody')]
    public function testAnonymousCallerIsServed(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/optional');

        self::assertResponseIsSuccessful();
        self::assertSame(['user' => null, 'roles' => []], self::json($client));
    }

    #[TestDox('a caller with a token reaches the same endpoint as themselves')]
    public function testIdentifiedCallerIsServed(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/optional', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::issuer()->issue('alice')->value,
        ]);

        self::assertResponseIsSuccessful();
        self::assertSame(['user' => 'alice', 'roles' => ['ROLE_USER']], self::json($client));
    }

    #[TestDox('the guarded endpoint next door still refuses the same anonymous caller')]
    public function testTheExemptionIsThePathAndNotTheFirewall(): void
    {
        // Without this the suite could not tell "the rule exempts this path"
        // from "the firewall stopped authenticating anything": both would serve
        // /api/optional to a caller with no token.
        $client = self::createClient();

        $client->request('GET', '/api/whoami');

        self::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    #[TestDox('a token that is present but garbled is refused, not ignored')]
    public function testGarbledTokenIsStillRefused(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/optional', server: ['HTTP_AUTHORIZATION' => 'Bearer not.a.jwt']);

        $response = $client->getResponse();

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());

        // With the challenge, so a client knows to present a different token
        // rather than that the endpoint is gone.
        self::assertStringContainsString('error="invalid_token"', (string) $response->headers->get('WWW-Authenticate'));
    }

    #[TestDox('an expired token is refused rather than quietly served as anonymous')]
    public function testExpiredTokenIsStillRefused(): void
    {
        // The case an application actually meets, and the one where a reading
        // of "optional" as "never fails" would be a silent degradation: a
        // caller whose session lapsed would see the anonymous page with no
        // signal that their token is the reason.
        $client = self::createClient();

        $token = self::issuer()->issue('alice', ttl: 60);
        self::clock()->tick(new DateInterval('PT2H'));

        $client->request('GET', '/api/optional', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);

        self::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    private static function issuer(): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function clock(): FrozenClock
    {
        $clock = self::getContainer()->get('test.frozen_clock');
        self::assertInstanceOf(FrozenClock::class, $clock);

        return $clock;
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
     * The frozen clock is what makes the expiry row above mean anything: on the
     * process clock a token minted seconds ago is valid whatever the test does
     * to it, and the assertion would pass for the wrong reason.
     *
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        return [
            'clock' => 'test.frozen_clock',
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => [
                'default' => [
                    'issuer' => 'https://issuer.test',
                    'key' => 'default',
                    'client_id' => 'test-client',
                    'audience' => 'https://api.test',
                ],
            ],
            'consumers' => [
                'api' => [
                    'issuer' => 'https://issuer.test',
                    'audience' => 'https://api.test',
                    'keys' => ['default'],
                    'allowed_algorithms' => ['HS256'],
                ],
            ],
        ];
    }
}
