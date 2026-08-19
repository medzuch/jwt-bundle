<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\ErrorHandler\ErrorHandler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The claim the bundle exists to make: a token this application minted gets its
 * bearer through this application's firewall, as the right user.
 *
 * Asserted through Symfony's own `access_token` authenticator and a real
 * controller, not by calling the handler — the wiring between them is precisely
 * what is under test.
 */
#[CoversClass(AccessTokenIssuer::class)]
final class RoundTripTest extends WebTestCase
{
    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    protected function tearDown(): void
    {
        parent::tearDown();

        $current = set_exception_handler(null);
        restore_exception_handler();

        if (is_array($current) && $current[0] instanceof ErrorHandler) {
            restore_exception_handler();
        }
    }

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration());
    }

    #[TestDox('a token minted by the configured issuer authenticates against the configured firewall')]
    public function testIssuedTokenAuthenticates(): void
    {
        $client = self::createClient();

        $token = self::issuer()->issue('alice');

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);

        self::assertResponseIsSuccessful();
        self::assertSame(['user' => 'alice'], self::json($client));
    }

    #[TestDox('the same endpoint refuses a request with no token')]
    public function testAnonymousRequestIsRefused(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/whoami');

        self::assertSame(Response::HTTP_UNAUTHORIZED, $client->getResponse()->getStatusCode());
    }

    #[TestDox('a garbled token is refused without leaking why')]
    public function testGarbledTokenIsRefused(): void
    {
        $client = self::createClient();

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer not.a.jwt']);

        $response = $client->getResponse();

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertStringNotContainsStringIgnoringCase('signature', (string) $response->getContent());
        self::assertStringNotContainsStringIgnoringCase('claim', (string) $response->getContent());
    }

    #[TestDox('the issued token reports the lifetime it was actually minted with')]
    public function testIssuedTokenCarriesItsLifetime(): void
    {
        self::bootKernel();

        self::assertSame(900, self::issuer()->issue('alice')->expiresIn);
        self::assertSame(60, self::issuer()->issue('alice', ttl: 60)->expiresIn);
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
    private static function json(KernelBrowser $client): array
    {
        $decoded = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        return [
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
