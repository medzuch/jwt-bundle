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
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpFoundation\Request;
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

    #[TestDox('the header still works beside it, and is consulted first')]
    public function testHeaderStillWorks(): void
    {
        $client = self::createClient();
        self::presentCookie($client, 'not-a-token');

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . self::token()]);

        self::assertResponseIsSuccessful();
    }

    #[TestDox('the cookie is not a fallback: any Authorization header at all ends the search')]
    public function testTheCookieIsNotAFallback(): void
    {
        // Symfony's chain returns the first non-empty extraction and stops, so
        // a browser carrying a stale token, or a Basic credential a proxy put
        // there, is answered 401 while a perfectly good cookie sits unread.
        // Pinned here so a later reordering cannot change it quietly.
        $client = self::createClient();
        self::presentCookie($client, self::token());

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer stale-and-invalid']);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    #[TestDox('a cookie holding nothing, or holding an array, is no token rather than a bad request')]
    public function testMalformedCookie(): void
    {
        // Through the extractor directly: neither value reaches the handler, so
        // over HTTP both are indistinguishable from no cookie at all — which is
        // the point. The array case is the one that matters: `name[]=x` is
        // something anyone able to set a cookie can send, and reading it with
        // InputBag::get() throws, answering 400 where the honest answer is that
        // this request carries no token.
        $extractor = new CookieTokenExtractor(self::COOKIE);

        $blank = Request::create('/api/whoami');
        $blank->cookies->set(self::COOKIE, '');
        self::assertNull($extractor->extractAccessToken($blank));

        $arrayValued = Request::create('/api/whoami');
        $arrayValued->cookies->set(self::COOKIE, ['nested' => 'value']);
        self::assertNull($extractor->extractAccessToken($arrayValued));

        $present = Request::create('/api/whoami');
        $present->cookies->set(self::COOKIE, 'a-token');
        self::assertSame('a-token', $extractor->extractAccessToken($present));
    }

    #[TestDox('a cookie name a browser could never send fails at container build')]
    public function testInvalidCookieName(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/RFC 6265/');

        (new SecuredKernel([
            'token_extractors' => ['cookie' => ['cookie' => 'jwt token;']],
        ]))->boot();
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
