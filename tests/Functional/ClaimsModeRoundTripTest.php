<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Security\Identity\ClaimsUserResolver;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * A user built from claims, through Symfony's own authenticator rather than by
 * calling the handler.
 *
 * The difference matters twice over: the badge's loader is only called by the
 * passport machinery, and the roles it produces only mean anything once an
 * access rule reads them. Both are asserted here, over HTTP.
 */
#[CoversClass(ClaimsUserResolver::class)]
final class ClaimsModeRoundTripTest extends WebTestCase
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

    #[TestDox('a token carrying scopes authenticates and brings its roles with it')]
    public function testClaimsModeThroughTheFirewall(): void
    {
        $client = self::createClient();
        $token = self::issuer()->issue('user-42', scopes: ['read', 'write']);

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);

        self::assertResponseIsSuccessful();

        $body = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($body);
        self::assertSame('user-42', $body['user'] ?? null);
        self::assertSame(['ROLE_USER', 'ROLE_read', 'ROLE_write'], $body['roles'] ?? null);
    }

    #[TestDox('authenticating a claims-mode user deprecates nothing that belongs to this bundle')]
    public function testNoDeprecationFromTheUser(): void
    {
        // Symfony 7.3 deprecated implementing UserInterface::eraseCredentials()
        // and skips the notice when the method carries #[\Deprecated]. The
        // notice arrives through a silenced @trigger_error, so PHPUnit's
        // deprecation display never shows it and only a handler of our own
        // catches it — which is exactly how it would go unnoticed in an
        // application, as one more line in its deprecation log attributed to
        // this bundle.
        $ours = [];
        set_error_handler(static function (int $level, string $message) use (&$ours): bool {
            if (\E_USER_DEPRECATED === $level && str_contains($message, 'Medzuch\\JwtBundle')) {
                $ours[] = $message;
            }

            return true;
        }, \E_ALL);

        try {
            $client = self::createClient();
            $token = self::issuer()->issue('user-42', scopes: ['read']);

            $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);
        } finally {
            restore_error_handler();
        }

        self::assertResponseIsSuccessful();
        self::assertSame([], $ours);
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
                'user' => [
                    'mode' => 'claims',
                    'roles' => ['claim' => 'scope', 'defaults' => ['ROLE_USER']],
                ],
            ]],
        ];
    }
}
