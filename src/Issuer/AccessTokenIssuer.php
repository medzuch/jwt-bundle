<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use DateInterval;
use Medzuch\Jwt\Profile\AccessTokenBuilder;
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
 * README "Claims an application adds" has the four claim sources, the order in
 * which each overrides the one before, and why `client_id` and `scope` are
 * closed to providers and listeners while configuration and `issue()` may still
 * set them.
 *
 * The builder is filled before any of those sources run and the assembled map
 * is applied on top of it, so nothing here guards the registered claims: the
 * library refuses them in `withClaim()`, whoever sends them.
 *
 * Where the issuer has a {@see TokenEnvelope}, what it returns is that token
 * sealed in a JWE (I8). Everything above happens first and happens the same
 * way: encryption is what the token travels in, not part of what it says.
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
        private readonly ?TokenEnvelope $envelope = null,
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

        $token = new IssuedToken($this->serialize($builder), $lifetime, $jti);

        $this->dispatcher?->dispatch(new JwtIssuedEvent($issuance, $assembled));

        return $token;
    }

    /**
     * A signed token, or that token sealed in a JWE where the issuer was given
     * a `jwe` block (I8). Sealing is the last thing that happens to it and
     * changes nothing above: the claims, the `jti` the caller may revoke on,
     * and the lifetime reported back are the token's own, and the envelope is
     * the wrapper it travels in.
     */
    private function serialize(AccessTokenBuilder $builder): string
    {
        $signed = $builder->build();

        return null === $this->envelope ? (string) $signed : $this->envelope->seal($signed);
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
