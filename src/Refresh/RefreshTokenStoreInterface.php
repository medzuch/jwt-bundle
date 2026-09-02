<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Refresh;

use InvalidArgumentException;

/**
 * Where refresh tokens live, which is your database and not this bundle.
 *
 * This package mints access tokens and verifies them; a refresh token is the
 * other half of a session, and it is stateful by nature — rotation, device
 * records, "log out everywhere", the row a support engineer deletes. All of
 * that is business logic over an application's own schema, which is why §8 of
 * `docs/plan.md` keeps storage outside the package permanently and ships this
 * shape instead. There is no entity here, no migration and no default
 * implementation: naming the operations is the whole of what a bundle can
 * usefully own.
 *
 * What the three methods are for:
 *
 * - {@see store()} records a freshly generated token against a subject. Persist
 *   {@see RefreshToken::$hash} and {@see RefreshToken::$expiresAt}; never
 *   persist {@see RefreshToken::$value}, which the client has and you do not
 *   need.
 * - {@see consume()} is the whole of a rotation, and it is one call rather than
 *   a find and a delete because the gap between those two is where a token gets
 *   spent twice. An implementation hashes what was presented with
 *   {@see RefreshToken::hashOf()}, finds the row, marks it spent and returns
 *   what it found — atomically, which for SQL means one `UPDATE ... WHERE
 *   hash = ? AND used_at IS NULL` and a look at the affected row count, not a
 *   `SELECT` followed by an `UPDATE`.
 * - {@see revokeAllFor()} ends every session a subject has. Called on a
 *   password change, on an account suspension, and on the reuse
 *   {@see RefreshTokenRecord::$alreadyUsed} reports.
 *
 * **A spent token is returned, not hidden.** `consume()` answers `null` only
 * for a token the store has never seen. One it has seen and already spent comes
 * back with `alreadyUsed: true`, because that is a different event and the
 * caller decides what it means — see {@see RefreshTokenRecord}. A store that
 * deletes rows on use cannot make that distinction and will answer `null`
 * twice; keeping spent rows until their own expiry is what buys it, and after
 * `expiresAt` there is nothing left to learn from the row.
 *
 * Nothing in this bundle calls this interface. It is a shape for application
 * code to implement and for application code to call, so that two Symfony
 * applications doing the same thing spell it the same way.
 */
interface RefreshTokenStoreInterface
{
    /**
     * @param string $subject whoever the token is for — the identifier your user provider loads
     *
     * @throws InvalidArgumentException when `$subject` is empty: a token belonging to nobody
     *                                  could never be exchanged for an access token
     */
    public function store(RefreshToken $token, string $subject): void;

    /**
     * Spend a token and say what it was.
     *
     * @param string $presented exactly what the client sent, unhashed
     *
     * @return RefreshTokenRecord|null the record, spent by this call or already spent before it;
     *                                 `null` when no such token was ever issued
     */
    public function consume(string $presented): ?RefreshTokenRecord;

    /**
     * Every token this subject holds stops working, spent or not.
     */
    public function revokeAllFor(string $subject): void;
}
