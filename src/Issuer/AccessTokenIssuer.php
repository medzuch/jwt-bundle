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
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims
     */
    public function issue(string $subject, array $scopes = [], array $claims = [], ?int $ttl = null): IssuedToken
    {
        $lifetime = $ttl ?? $this->ttl;

        $builder = $this->profile->issue()
            ->subject($subject)
            ->audience($this->audience)
            ->clientId($this->clientId)
            ->expiresIn(new DateInterval(sprintf('PT%dS', $lifetime)));

        if ([] !== $scopes) {
            $builder = $builder->scope($scopes);
        }

        foreach (array_merge($this->staticClaims, $claims) as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return new IssuedToken((string) $builder->build(), $lifetime);
    }
}
