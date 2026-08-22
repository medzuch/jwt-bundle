<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use DateInterval;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Event\JwtIssuedEvent;
use Medzuch\JwtBundle\Event\JwtIssuingEvent;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Mints RFC 9068 access tokens for one configured issuer.
 *
 * The profile supplies `iss`, `iat`, `jti` and the `at+jwt` header; this adds
 * the configured audience, client id and TTL, and whatever the caller passes.
 *
 * Four sources of claims, in the order they are applied, each able to override
 * the one before it:
 *
 * 1. static claims from configuration — the same for every token;
 * 2. `TokenClaimProviderInterface` services, in tag priority order — the same
 *    for every token too, but decided by code that can look things up;
 * 3. the caller's `$claims` argument — this token, said explicitly;
 * 4. listeners on `JwtIssuingEvent` — last, because adjusting a claim set means
 *    seeing all of it.
 *
 * The profile's own claims are applied after all four and cannot be overridden
 * by any of them.
 *
 * Two claims deserve naming, because they are not registered claims and so the
 * library does not protect them: a static or per-call claim called `client_id`
 * or `scope` silently replaces the configured client id or the `$scopes`
 * argument. That follows from "a caller can override one deliberately", but
 * both carry RFC 9068 meaning, so overriding either should be a decision — and
 * only sources 1 and 3 are allowed to make it. A provider or a listener runs
 * for tokens it was not asked about; both are refused these names.
 */
final class AccessTokenIssuer
{
    /**
     * @param non-empty-list<string>                $audience
     * @param array<string, mixed>                  $staticClaims
     * @param iterable<TokenClaimProviderInterface> $providers
     */
    public function __construct(
        private readonly AccessTokenProfile $profile,
        private readonly string $name,
        private readonly array $audience,
        private readonly string $clientId,
        private readonly int $ttl,
        private readonly array $staticClaims = [],
        private readonly iterable $providers = [],
        private readonly ?EventDispatcherInterface $dispatcher = null,
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

        $issuance = new TokenIssuance($this->name, $subject, $scopes, $audience ?? $this->audience, $lifetime, $jti);

        $builder = $this->profile->issue()
            ->subject($subject)
            ->audience($issuance->audience)
            ->clientId($this->clientId)
            ->jwtId($jti)
            ->expiresIn(new DateInterval(sprintf('PT%dS', $lifetime)));

        if ([] !== $scopes) {
            $builder = $builder->scope($scopes);
        }

        $assembled = $this->assemble($issuance, $claims);

        foreach ($assembled as $claim => $value) {
            $builder = $builder->withClaim($claim, $value);
        }

        $token = new IssuedToken((string) $builder->build(), $lifetime, $jti);

        $this->dispatcher?->dispatch(new JwtIssuedEvent($issuance, $assembled));

        return $token;
    }

    /**
     * @param array<string, mixed> $callerClaims
     *
     * @return array<string, mixed>
     */
    private function assemble(TokenIssuance $issuance, array $callerClaims): array
    {
        $claims = $this->staticClaims;

        foreach ($this->providers as $provider) {
            $contributed = $provider->claimsFor($issuance);

            ReservedClaims::refuse(array_keys($contributed), sprintf('Claim provider "%s"', $provider::class));

            // array_replace, not array_merge: the claims map allows any JSON
            // object key, and array_merge renumbers integer-like string keys
            // instead of overriding them — a caller could not override a static
            // claim named "1", and both would land in the token under invented
            // names.
            $claims = array_replace($claims, $contributed);
        }

        $claims = array_replace($claims, $callerClaims);

        if (null === $this->dispatcher) {
            return $claims;
        }

        $event = new JwtIssuingEvent($issuance, $claims);
        $this->dispatcher->dispatch($event);

        return $event->claims();
    }
}
