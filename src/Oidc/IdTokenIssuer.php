<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Oidc;

use DateInterval;
use InvalidArgumentException;
use Medzuch\Jwt\Profile\IdTokenBuilder;
use Medzuch\Jwt\Profile\IdTokenProfile;

/**
 * Mints OpenID Connect ID tokens for one configured provider identity (I6) —
 * the end of the pair {@see IdTokenVerifier} reads from the other side.
 *
 * **It hands back the library's builder rather than a token**, for the reason
 * {@see \Medzuch\JwtBundle\SecurityEvent\SecurityEventIssuer} does: what varies
 * between two ID tokens is `nonce`, `auth_time`, `acr`, `amr`, `azp` and
 * whatever profile claims the scopes granted — and no argument list this bundle
 * could invent would express those better than {@see IdTokenBuilder}, which has
 * a typed setter for each. An access token is the opposite case, and
 * {@see \Medzuch\JwtBundle\Issuer\AccessTokenIssuer} returns a token
 * accordingly.
 *
 * The profile supplies `iss` and `iat`; this adds the audience and the
 * lifetime; the caller adds the subject, whatever the flow produced, and calls
 * `build()`.
 *
 * **An ID token is not a credential.** It says who signed in and how, to the
 * client that asked — OIDC Core §2. It is not a bearer token for an API, and
 * this bundle's consumers will not accept one: they verify the RFC 9068
 * access-token profile, whose `typ` is `at+jwt`. Minting an ID token to
 * authenticate a request would be using the wrong half of OIDC, and the
 * refusal that follows is the design working.
 */
final class IdTokenIssuer
{
    /**
     * @param ?string $clientId the relying party every token from here is for, where
     *                          there is only one. Null asks the caller, which is the
     *                          ordinary answer for a provider serving several clients
     */
    public function __construct(
        private readonly IdTokenProfile $profile,
        private readonly int $ttl,
        private readonly ?string $clientId = null,
    ) {}

    /**
     * A builder with the identity, the audience and the lifetime applied.
     *
     * ```php
     * $idToken = $issuer->issue('client-42')
     *     ->subject($user->getId())
     *     ->nonce($request->nonce)
     *     ->authTime($session->authenticatedAt)
     *     ->withClaim('email', $user->email)
     *     ->build();
     * ```
     *
     * @param ?string $clientId the relying party this token is for, which for a
     *                          provider with several is the one the authorization
     *                          request named. Null uses the configured default
     *
     * @throws InvalidArgumentException where neither names a client, since an ID
     *                                  token with no audience is one no relying party may accept
     *                                  (OIDC Core §3.1.3.7)
     */
    public function issue(?string $clientId = null): IdTokenBuilder
    {
        $audience = $clientId ?? $this->clientId;

        if (null === $audience || '' === $audience) {
            throw new InvalidArgumentException('An ID token has to name the relying party it is for. Pass the client id to issue(), or configure one under medzuch_jwt.id_token_issuers.<name>.client_id for an application that serves a single client.');
        }

        return $this->profile->issue()
            ->audience($audience)
            ->expiresIn(new DateInterval(sprintf('PT%dS', $this->ttl)));
    }
}
