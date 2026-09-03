<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use DateTimeImmutable;
use InvalidArgumentException;
use Medzuch\JwtBundle\Refresh\RefreshToken;
use Medzuch\JwtBundle\Refresh\RefreshTokenRecord;
use Medzuch\JwtBundle\Refresh\RefreshTokenStoreInterface;

/**
 * An implementation of the contract, kept in an array.
 *
 * Not shipped, and not a suggestion to ship one: a store belongs in a database,
 * because "log out everywhere" and "this token was replayed" are questions
 * asked across processes and deployments. What this is for is proving that the
 * interface can be implemented as written — that `consume()` really can spend
 * a token and report a previous spend in one call — and giving the suite the
 * rotation flow to exercise.
 *
 * Rows are kept after they are spent, until their own expiry, which is what
 * lets a second presentation be answered with `alreadyUsed: true` rather than
 * with silence. A store that deleted them would answer `null` and the caller
 * could not tell a replay from a typo.
 *
 * It is also read as documentation, so the spend below names the flag it is
 * about to overwrite instead of relying on PHP having copied the row. The
 * equivalent in SQL is one `UPDATE ... WHERE hash = ? AND used_at IS NULL` and
 * a look at the affected row count — an implementation that sets the flag and
 * then reads it back reports every first use as a replay.
 */
final class InMemoryRefreshTokenStore implements RefreshTokenStoreInterface
{
    /** @var array<string, array{subject: string, grant: string|null, expiresAt: DateTimeImmutable, used: bool}> */
    private array $rows = [];

    public function store(RefreshToken $token, string $subject, ?string $grant = null): void
    {
        if ('' === $subject) {
            throw new InvalidArgumentException('A refresh token belonging to nobody could never be exchanged.');
        }

        // A token is minted once. Storing one twice would either be the caller
        // repeating itself or a value that is not as unique as it claims, and
        // silently overwriting the row would un-spend a token already used.
        if (isset($this->rows[$token->hash])) {
            throw new InvalidArgumentException('This token is already stored; `store()` takes a freshly generated one.');
        }

        // The hash, never the value: what the client holds is the client's.
        $this->rows[$token->hash] = [
            'subject' => $subject,
            'grant' => $grant,
            'expiresAt' => $token->expiresAt,
            'used' => false,
        ];
    }

    public function consume(string $presented): ?RefreshTokenRecord
    {
        // A form field nobody filled in is the same event as a string nobody
        // was ever issued, and the caller answers both with `invalid_grant`.
        if ('' === $presented) {
            return null;
        }

        $hash = RefreshToken::hashOf($presented);
        $row = $this->rows[$hash] ?? null;

        if (null === $row) {
            return null;
        }

        // The flag as it stood *before* this call is what `alreadyUsed` means,
        // so it is read out before the row is marked.
        $alreadyUsed = $row['used'];
        $this->rows[$hash]['used'] = true;

        return new RefreshTokenRecord($row['subject'], $row['expiresAt'], $alreadyUsed, $row['grant']);
    }

    public function revokeGrant(string $grant): void
    {
        if ('' === $grant) {
            throw new InvalidArgumentException('An empty grant names no lineage to revoke.');
        }

        foreach ($this->rows as $hash => $row) {
            if ($row['grant'] === $grant) {
                unset($this->rows[$hash]);
            }
        }
    }

    public function revokeAllFor(string $subject): void
    {
        if ('' === $subject) {
            throw new InvalidArgumentException('An empty subject names nobody whose sessions could be ended.');
        }

        foreach ($this->rows as $hash => $row) {
            if ($row['subject'] === $subject) {
                unset($this->rows[$hash]);
            }
        }
    }

    /**
     * How many rows a subject still has, for a test that wants to see the
     * sessions emptied rather than infer it from a later refusal.
     */
    public function countFor(string $subject): int
    {
        return count(array_filter($this->rows, static fn(array $row): bool => $row['subject'] === $subject));
    }

    /**
     * Whether the presented value survived anywhere in the store — as a key or
     * as a field — which it must not.
     */
    public function holdsPlaintext(string $value): bool
    {
        if (array_key_exists($value, $this->rows)) {
            return true;
        }

        foreach ($this->rows as $row) {
            if (in_array($value, [$row['subject'], $row['grant']], true)) {
                return true;
            }
        }

        return false;
    }
}
