<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

/**
 * Contributes claims to every token an issuer mints.
 *
 * Implement it and autoconfiguration does the rest. README "Claims an
 * application adds" has the ordering, how a provider serving one issuer of
 * several says so, and the claims a provider may not set — the registered ones,
 * `client_id` and `scope`, all of which throw.
 */
interface TokenClaimProviderInterface
{
    /**
     * @return array<string, mixed> claim name => value, `[]` to contribute nothing
     */
    public function claimsFor(TokenIssuance $issuance): array;
}
