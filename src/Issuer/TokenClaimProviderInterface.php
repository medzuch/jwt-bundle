<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

/**
 * Contributes claims to every token an issuer mints.
 *
 * Implement it, and autoconfiguration does the rest: a tenant id, an email, an
 * entitlement list end up in the token without the application subclassing the
 * issuer or repeating the claim at every call site. Providers run in tag
 * priority order, and a later one overrides an earlier one's claim.
 *
 * A provider runs for every issuer. With more than one configured, filtering is
 * the provider's own decision — `$issuance->issuerName` is there for it, and
 * returning `[]` contributes nothing.
 *
 * What a provider may not set is the claims the issuer itself decides: the
 * registered claims (RFC 7519 §4.1), `client_id` and `scope`. A provider runs
 * for tokens it knows nothing about, and one quietly rewriting the scope of
 * every token is a hole rather than a feature; the caller's own `issue()`
 * arguments are where a token's scope is chosen. Returning one throws.
 */
interface TokenClaimProviderInterface
{
    /**
     * @return array<string, mixed> claim name => value, `[]` to contribute nothing
     */
    public function claimsFor(TokenIssuance $issuance): array;
}
