<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Http;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * The challenge a resource server owes a caller that presented no credentials:
 * `401` with `WWW-Authenticate: Bearer` (RFC 6750 §3).
 *
 * Symfony answers a token it rejects on its own, with `error="invalid_token"`
 * and a generic description. What it has no answer for is the request that
 * carried no token at all — the authenticator does not run, and a firewall
 * without an entry point produces a bare 401 with nothing saying how to
 * authenticate.
 *
 * **No `error` here, deliberately.** RFC 6750 §3 says a request lacking
 * authentication information should not be told which error it made, and it is
 * right: `error="invalid_token"` for a request that sent no token describes a
 * failure that did not happen, and a client reading it would go looking for a
 * bad token it never had.
 */
final class BearerEntryPoint implements AuthenticationEntryPointInterface
{
    public function __construct(private readonly string $realm) {}

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED, [
            'WWW-Authenticate' => sprintf('Bearer realm="%s"', $this->realm),
        ]);
    }
}
