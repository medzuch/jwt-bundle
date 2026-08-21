<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use DateInterval;
use Medzuch\Jwt\Profile\AccessTokenProfile;

/**
 * Mints RFC 9068 access tokens for one configured issuer.
 *
 * The profile supplies `iss`, `iat`, `jti` and the `at+jwt` header; this adds
 * the configured audience, client id and TTL, and whatever the caller passes.
 * Static claims from configuration are applied first, so a caller can override
 * one deliberately, and the profile's own claims are applied last and cannot be
 * overridden at all.
 *
 * Two claims deserve naming, because they are not registered claims and so the
 * library does not protect them: a static or per-call claim called `client_id`
 * or `scope` silently replaces the configured client id or the `$scopes`
 * argument. That follows from "a caller can override one deliberately", but
 * both carry RFC 9068 meaning, so overriding either should be a decision.
 */
final class AccessTokenIssuer
{
    /**
     * @param non-empty-list<string> $audience
     * @param array<string, mixed>   $staticClaims
     */
    public function __construct(
        private readonly AccessTokenProfile $profile,
        private readonly array $audience,
        private readonly string $clientId,
        private readonly int $ttl,
        private readonly array $staticClaims = [],
    ) {}

    /**
     * @param list<string>                $scopes
     * @param array<string, mixed>        $claims
     * @param non-empty-list<string>|null $audience narrows `aud` for one token, for
     *                                             minting to one of several resource servers; null uses the configured audience
     */
    public function issue(
        string $subject,
        array $scopes = [],
        array $claims = [],
        ?int $ttl = null,
        ?array $audience = null,
    ): IssuedToken {
        $lifetime = $ttl ?? $this->ttl;

        // The profile mints a `jti` of its own, and keeps it: what comes back
        // is a compact string. Naming it here is what lets the caller revoke
        // this token later without parsing it open again.
        $jti = bin2hex(random_bytes(16));

        $builder = $this->profile->issue()
            ->subject($subject)
            ->audience($audience ?? $this->audience)
            ->clientId($this->clientId)
            ->jwtId($jti)
            ->expiresIn(new DateInterval(sprintf('PT%dS', $lifetime)));

        if ([] !== $scopes) {
            $builder = $builder->scope($scopes);
        }

        // array_replace, not array_merge: the claims map allows any JSON
        // object key, and array_merge renumbers integer-like string keys
        // instead of overriding them — a caller could not override a static
        // claim named "1", and both would land in the token under invented
        // names.
        foreach (array_replace($this->staticClaims, $claims) as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return new IssuedToken((string) $builder->build(), $lifetime, $jti);
    }
}
