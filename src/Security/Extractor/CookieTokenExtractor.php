<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Extractor;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\AccessToken\AccessTokenExtractorInterface;

/**
 * Takes the token from a cookie, for the one caller that cannot hold it
 * anywhere better: a browser.
 *
 * Symfony ships extractors for the `Authorization` header, the query string and
 * a form-encoded body; this is the missing one. A single-page application that
 * keeps its token in JavaScript keeps it where any injected script can read it,
 * so a `HttpOnly` cookie is the safer place — and then something has to read
 * the token back off the request, which the header extractor cannot.
 *
 * **What the cookie costs.** The browser attaches it to requests this
 * application did not initiate, which is what CSRF is. A token in an
 * `Authorization` header is immune by construction, because nothing attaches
 * one for you. Moving to a cookie buys protection from script access and takes
 * on cross-site request forgery in exchange, and neither this extractor nor
 * anything else in the bundle can close that on its own: the cookie needs
 * `SameSite`, and state-changing routes need their own defence.
 *
 * @internal
 */
final class CookieTokenExtractor implements AccessTokenExtractorInterface
{
    private const CROSS_SITE = 'cross-site';

    /**
     * @param bool $sameSiteOnly refuse a request the browser reports as coming from
     *                           another site, where it says so at all
     */
    public function __construct(
        private readonly string $cookie,
        private readonly bool $sameSiteOnly = false,
    ) {}

    public function extractAccessToken(Request $request): ?string
    {
        // Defence in depth, not a CSRF defence: `Sec-Fetch-Site` is sent by
        // current browsers and by nothing else, so a request without it is
        // unjudged rather than refused — an API client, an old browser, a
        // forged request from either. What it does close is the ordinary
        // cross-site form post from a browser that does tell the truth.
        if ($this->sameSiteOnly && self::CROSS_SITE === $request->headers->get('Sec-Fetch-Site')) {
            return null;
        }

        // Read through all(), not get(): an array-valued cookie — `name[]=x`,
        // which anyone able to set a cookie can send — makes InputBag::get()
        // throw, and a malformed cookie would answer 400 where it should answer
        // "no token here" and let the request be refused as unauthenticated.
        $token = $request->cookies->all()[$this->cookie] ?? null;

        return is_string($token) && '' !== $token ? $token : null;
    }
}
