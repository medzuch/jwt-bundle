<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

/**
 * What is being minted, handed to everything the application hooks into
 * issuance: claim providers (I3) and the events around them (I4).
 *
 * Read-only on purpose. A hook adjusts the claims map it is given; the subject,
 * scopes, audience and lifetime were decided by whoever called `issue()`, and a
 * hook rewriting them would mint a token the caller did not ask for and cannot
 * see. The `jti` is here because it exists before anything is signed, so an
 * audit hook can record a token it will later be asked to revoke.
 *
 * `$issuerName` is the configured name — `default`, `partners` — not the `iss`
 * value. It is what an application writes in its own configuration, and so what
 * a provider serving one issuer of several recognises.
 */
final class TokenIssuance
{
    /**
     * @param list<string>           $scopes
     * @param non-empty-list<string> $audience
     */
    public function __construct(
        public readonly string $issuerName,
        public readonly string $subject,
        public readonly array $scopes,
        public readonly array $audience,
        public readonly int $ttl,
        public readonly string $jti,
    ) {}
}
