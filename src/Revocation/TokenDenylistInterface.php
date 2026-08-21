<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Revocation;

use DateTimeImmutable;

/**
 * Tokens refused before their own expiry says so.
 *
 * A JWT is valid because it verifies, not because anyone is still willing to
 * accept it, which is the trade that makes it stateless. Revocation buys that
 * willingness back for the cases that need it — a logout, a leaked token, an
 * account suspended mid-session — and costs a lookup per request to do it.
 *
 * Keyed on `jti`, which RFC 9068 §2.2 makes a required claim, so every access
 * token this bundle accepts has one to be named by.
 *
 * An entry only has to outlive the token carrying it: after `exp` the token is
 * refused anyway, and an entry kept beyond that is a row nobody will ever read
 * (DEC-3). That is why revoking takes the moment to hold until rather than a
 * duration, and why the implementation this bundle ships is a cache.
 */
interface TokenDenylistInterface
{
    /**
     * @param DateTimeImmutable $until the token's own expiry. An implementation that
     *                                 expires its entries must keep this one until the consumer stops accepting
     *                                 the token, which is `$until` plus the consumer's leeway — the shipped one
     *                                 is told that tolerance and adds it, so callers pass the plain `exp`
     */
    public function revoke(string $jti, DateTimeImmutable $until): void;

    public function isRevoked(string $jti): bool;
}
