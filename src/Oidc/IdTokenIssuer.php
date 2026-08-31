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
 * The profile supplies `iss` and `iat`; this adds the subject, the audience
 * and the lifetime; the caller adds whatever the flow produced and calls
 * `build()`. Those three are arguments rather than the caller's to chain
 * because OIDC Core §2 makes `sub`, `aud` and `exp` mandatory: they do not vary
 * in the way `nonce` and `acr` do, and a token missing one is a token every
 * relying party refuses — including this bundle's own.
 *
 * **Issuance is not announced.** {@see \Medzuch\JwtBundle\Event\JwtIssuingEvent}
 * and {@see \Medzuch\JwtBundle\Event\JwtIssuedEvent} are not dispatched here,
 * and an application auditing on the second will not see identity issuance. The
 * reason is not the one {@see \Medzuch\JwtBundle\SecurityEvent\SecurityEventIssuer}
 * gives — an ID token issuance has exactly the shape a
 * {@see \Medzuch\JwtBundle\Issuer\TokenIssuance} carries — but that handing back
 * a builder means there is no moment at which this sees the finished claim set:
 * the token is assembled after the last line of code here has run. Auditing what
 * an OP issued therefore belongs to the caller, which holds the built token, or
 * to an event of its own; it is deliberately not the access-token one dispatched
 * over a value that was never assembled.
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
     * A builder with the subject, the audience and the lifetime applied.
     *
     * ```php
     * $idToken = $issuer->issue($user->getId(), 'client-42')
     *     ->nonce($request->nonce)
     *     ->authTime($session->authenticatedAt)
     *     ->withClaim('email', $user->email)
     *     ->build();
     * ```
     *
     * @param string  $subject  who authenticated, as this provider identifies them —
     *                          the `sub` a relying party will store
     * @param ?string $clientId the relying party this token is for, which for a
     *                          provider with several is the one the authorization
     *                          request named. Null uses the configured default
     *
     * @throws InvalidArgumentException where the subject is blank, or where neither
     *                                  argument nor configuration names a client: an ID token missing
     *                                  either is one no relying party may accept (OIDC Core §2)
     */
    public function issue(string $subject, ?string $clientId = null): IdTokenBuilder
    {
        if ('' === trim($subject)) {
            throw new InvalidArgumentException('An ID token has to say who authenticated. Pass the subject to issue(): OIDC Core §2 makes `sub` required, and a relying party refuses a token without one.');
        }

        $audience = trim($clientId ?? $this->clientId ?? '');

        if ('' === $audience) {
            throw new InvalidArgumentException('An ID token has to name the relying party it is for. Pass the client id to issue(), or configure one under medzuch_jwt.id_token_issuers.<name>.client_id for an application that serves a single client.');
        }

        return $this->profile->issue()
            ->subject($subject)
            ->audience($audience)
            ->expiresIn(new DateInterval(sprintf('PT%dS', $this->ttl)));
    }
}
