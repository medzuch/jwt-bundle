<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Security\Extractor\CookieTokenExtractor;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * A token carried by a cookie, through the firewall that reads it.
 *
 * The extractor is only half of the feature — the other half is an application
 * naming it in `token_extractors`, which is what these assert by going over
 * HTTP rather than calling `extractAccessToken()` directly.
 */
#[CoversClass(CookieTokenExtractor::class)]
final class CookieExtractorTest extends WebTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    private const COOKIE = '__Host-jwt';

    /**
     * The option travels through createClient(), which is what it is for: a
     * static flag reset in tearDown() would be one more thing to get right for
     * every test that follows.
     *
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration(true === ($options['same_site_only'] ?? false)));
    }

    #[TestDox('a token in the cookie authenticates, with no Authorization header in sight')]
    public function testCookieAuthenticates(): void
    {
        $client = self::createClient();
        self::presentCookie($client, self::token());

        $client->request('GET', '/api/whoami');

        self::assertResponseIsSuccessful();
    }

    #[TestDox('the header still works beside it, and takes precedence')]
    public function testHeaderStillWorks(): void
    {
        $client = self::createClient();
        self::presentCookie($client, 'not-a-token');

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token()]);

        self::assertResponseIsSuccessful();
    }

    #[TestDox('another cookie is not the one configured')]
    public function testOtherCookiesAreIgnored(): void
    {
        $client = self::createClient();
        $client->getCookieJar()->set(new Cookie('session', self::token(), null, '/', 'localhost'));

        $client->request('GET', '/api/whoami');

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    #[TestDox('by default a cross-site request is still read: the browser sends the cookie either way')]
    public function testCrossSiteIsAcceptedByDefault(): void
    {
        $client = self::createClient();
        self::presentCookie($client, self::token());

        $client->request('GET', '/api/whoami', server: ['HTTP_SEC_FETCH_SITE' => 'cross-site']);

        // Not a hole this extractor opened — it is what a cookie means, and why
        // the README asks for SameSite and CSRF defence beside it.
        self::assertResponseIsSuccessful();
    }

    #[TestDox('with same_site_only the browser saying "cross-site" is enough to ignore the cookie')]
    public function testCrossSiteIsRefusedWhenAsked(): void
    {
        $client = self::createClient(['same_site_only' => true]);
        self::presentCookie($client, self::token());

        $client->request('GET', '/api/whoami', server: ['HTTP_SEC_FETCH_SITE' => 'cross-site']);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    #[TestDox('same_site_only judges only what the browser reports, and same-site requests pass')]
    public function testSameSiteRequestsPass(): void
    {
        $client = self::createClient(['same_site_only' => true]);
        self::presentCookie($client, self::token());

        $client->request('GET', '/api/whoami', server: ['HTTP_SEC_FETCH_SITE' => 'same-origin']);
        self::assertResponseIsSuccessful();

        // No header at all: an API client, or a browser too old to send one.
        // Unjudged rather than refused, which the docblock says out loud.
        $client->request('GET', '/api/whoami');
        self::assertResponseIsSuccessful();
    }

    private static function presentCookie(KernelBrowser $client, string $value): void
    {
        $client->getCookieJar()->set(new Cookie(self::COOKIE, $value, null, '/', 'localhost'));
    }

    private static function token(): string
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer->issue('alice')->value;
    }

    /**
     * @return array<string, mixed>
     */
    private static function configuration(bool $sameSiteOnly): array
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
            ]],
            'token_extractors' => ['cookie' => ['cookie' => self::COOKIE, 'same_site_only' => $sameSiteOnly]],
        ];
    }
}
