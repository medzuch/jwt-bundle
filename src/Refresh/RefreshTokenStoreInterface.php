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
 * **What these four operations are, and what they are not.** They answer one
 * question — *is this presented string a live refresh token, and whose?* — and
 * give you the two revocations RFC 9700 §4.14.2 asks for. They do not model a
 * session. Scopes to re-issue, the client a token is bound to, a device name,
 * a last-used timestamp: all of that belongs to your own store class, which
 * implements this interface and carries whatever else your `refresh()` needs.
 * Type-hint your class where you need those; type-hint this interface where
 * the four operations are all you want to say. RFC 9700 §4.14.2 requires that
 * a refresh token be bound to the scope consented to, so a compliant
 * authorization server keeps more than this — the interface is the part worth
 * standardising, not the whole record.
 *
 * The operations:
 *
 * - {@see store()} records a freshly generated token against a subject, and
 *   optionally against the grant it descends from. Persist
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
 * - {@see revokeGrant()} ends one lineage: the tokens that descend from a
 *   single authorization. This is the reaction RFC 9700 §4.14.2 names — "it
 *   will revoke the active refresh token", at the cost of making that client
 *   authorize again — and it is the one to reach for when
 *   {@see RefreshTokenRecord::$alreadyUsed} reports a replay.
 * - {@see revokeAllFor()} is the wider hammer, for the events the same section
 *   lists separately: a password change, a logout at the authorization server.
 *   Every session the subject has, on every device.
 *
 * **A spent token is returned, not hidden.** `consume()` answers `null` for a
 * token the store has never seen — and for an empty presentation, which is the
 * same event seen from a form field nobody filled in. One it has seen and
 * already spent comes back with `alreadyUsed: true`, because that is a
 * different event and the caller decides what it means. A store that deletes
 * rows on use cannot make that distinction and will answer `null` twice;
 * keeping spent rows until their own expiry is what buys it, and after
 * `expiresAt` there is nothing left to learn from the row.
 *
 * **After a revocation, that promise lapses.** A revoked token may be marked or
 * deleted, whichever suits your schema: the family is already dead, every
 * answer is a refusal, and `null` and `alreadyUsed` mean the same thing from
 * there on. Pruning is yours too — rows are worth keeping until `expiresAt`
 * and are worth deleting after it, and no method here does that for you.
 *
 * Nothing in this bundle calls this interface. It is a shape for application
 * code to implement and for application code to call, so that two Symfony
 * applications doing the same thing spell it the same way. Implementing it does
 * not register it: alias your class to this interface in `services.yaml` if you
 * want to inject the interface rather than the class.
 */
interface RefreshTokenStoreInterface
{
    /**
     * A token this store has not seen before, minted moments ago.
     *
     * @param string      $subject whoever the token is for — the identifier your user provider loads
     * @param string|null $grant   the lineage it descends from, where an application models one:
     *                             the previous token's {@see RefreshTokenRecord::$grant} on a
     *                             rotation, a fresh identifier on a first issue
     *
     * @throws InvalidArgumentException when `$subject` is empty: a token belonging to nobody
     *                                  could never be exchanged for an access token
     */
    public function store(RefreshToken $token, string $subject, ?string $grant = null): void;

    /**
     * Spend a token and say what it was.
     *
     * @param string $presented exactly what the client sent, unhashed
     *
     * @return RefreshTokenRecord|null the record, spent by this call or already spent before it;
     *                                 `null` when no such token was ever issued, and for an empty
     *                                 string, so that a missing request parameter is an
     *                                 `invalid_grant` rather than an exception
     */
    public function consume(string $presented): ?RefreshTokenRecord;

    /**
     * One lineage stops working — the replay reaction of RFC 9700 §4.14.2.
     *
     * @throws InvalidArgumentException when `$grant` is empty: there is no lineage to end,
     *                                  and a store that treated it as "all of them" would revoke
     *                                  far more than the caller asked
     */
    public function revokeGrant(string $grant): void;

    /**
     * Every token this subject holds stops working, spent or not, on every
     * device. For a password change or a logout, not for a replay.
     *
     * @throws InvalidArgumentException when `$subject` is empty, for the same reason
     *                                  {@see store()} refuses one
     */
    public function revokeAllFor(string $subject): void;
}
