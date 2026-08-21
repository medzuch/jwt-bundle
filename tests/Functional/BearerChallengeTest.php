<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateTimeImmutable;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;
use Medzuch\JwtBundle\Security\Http\BearerEntryPoint;
use Medzuch\JwtBundle\Security\Http\InsufficientScopeHandler;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * What a resource server tells a caller it refused (RFC 6750 §3).
 *
 * Three answers, and the difference between them is the point: no credentials
 * is a challenge without an error, a token it will not accept is
 * `invalid_token` and nothing more, and a caller who is who they say but may
 * not do this is `insufficient_scope` with the scope that would have sufficed.
 */
#[CoversClass(BearerEntryPoint::class)]
#[CoversClass(InsufficientScopeHandler::class)]
final class BearerChallengeTest extends WebTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration());
    }

    #[TestDox('a request with no token is challenged, and told of no error it did not make')]
    public function testNoCredentials(): void
    {
        $client = self::createClient();
        $client->request('GET', '/api/whoami');

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);

        $challenge = self::challenge($client);
        self::assertSame('Bearer realm="reports-api"', $challenge);
        self::assertStringNotContainsString('error=', $challenge, 'RFC 6750 §3: a request that sent nothing made no error');
    }

    #[TestDox('a token that is not accepted is invalid_token, and says nothing about why')]
    public function testRejectedToken(): void
    {
        $client = self::createClient();

        $token = self::issuer()->issue('alice');
        self::denylist()->revoke($token->jti, new DateTimeImmutable('+1 hour'));

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);

        $challenge = self::challenge($client);
        self::assertStringContainsString('error="invalid_token"', $challenge);

        // The handler's own message names the reason — revoked, wrong
        // audience, no identity claim — and none of it belongs on the wire.
        self::assertStringNotContainsString('revoked', $challenge);
    }

    #[TestDox('a missing scope is insufficient_scope, and names the scope that would have done')]
    public function testInsufficientScope(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/scoped', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::issuer()->issue('alice', ['profile'])->value,
        ]);

        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Naming it is not a leak: the caller is authenticated, and the scope
        // is one they could ask their authorization server for. Withholding it
        // leaves them retrying a request that can never succeed.
        self::assertSame(
            'Bearer realm="reports-api", error="insufficient_scope", scope="reports.read"',
            self::challenge($client),
        );
    }

    #[TestDox('a denial that is not about scope is left to Symfony')]
    public function testOtherDenialsAreUntouched(): void
    {
        $client = self::createClient();

        // `^/api/role` requires a role this token does not carry: a 403 with no
        // bearer challenge, because there is no scope to name.
        $client->request('GET', '/api/role', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::issuer()->issue('alice')->value,
        ]);

        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);
        self::assertNull($client->getResponse()->headers->get('WWW-Authenticate'));
    }

    private static function challenge(KernelBrowser $client): string
    {
        $header = $client->getResponse()->headers->get('WWW-Authenticate');
        self::assertIsString($header);

        return $header;
    }

    private static function issuer(): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function denylist(): TokenDenylistInterface
    {
        $denylist = self::getContainer()->get('medzuch_jwt.denylist.api');
        self::assertInstanceOf(TokenDenylistInterface::class, $denylist);

        return $denylist;
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
                'realm' => 'reports-api',
                'denylist' => ['cache' => 'test.cache'],
                'user' => ['mode' => 'claims', 'roles' => ['claim' => 'scope']],
            ]],
        ];
    }
}
