<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

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
 */
final class InMemoryRefreshTokenStore implements RefreshTokenStoreInterface
{
    /** @var array<string, array{subject: string, expiresAt: \DateTimeImmutable, used: bool}> */
    private array $rows = [];

    public function store(RefreshToken $token, string $subject): void
    {
        if ('' === $subject) {
            throw new InvalidArgumentException('A refresh token belonging to nobody could never be exchanged.');
        }

        // The hash, never the value: what the client holds is the client's.
        $this->rows[$token->hash] = ['subject' => $subject, 'expiresAt' => $token->expiresAt, 'used' => false];
    }

    public function consume(string $presented): ?RefreshTokenRecord
    {
        $hash = RefreshToken::hashOf($presented);
        $row = $this->rows[$hash] ?? null;

        if (null === $row) {
            return null;
        }

        // Spend and report in one step. An array is atomic by being one
        // process; a database does this with a conditional UPDATE and a look
        // at the affected row count.
        $this->rows[$hash]['used'] = true;

        return new RefreshTokenRecord($row['subject'], $row['expiresAt'], $row['used']);
    }

    public function revokeAllFor(string $subject): void
    {
        foreach ($this->rows as $hash => $row) {
            if ($row['subject'] === $subject) {
                unset($this->rows[$hash]);
            }
        }
    }

    /**
     * How many rows a subject still has, for a test that wants to see the
     * family emptied rather than infer it from a later refusal.
     */
    public function countFor(string $subject): int
    {
        return count(array_filter($this->rows, static fn(array $row): bool => $row['subject'] === $subject));
    }

    /**
     * Whether the store kept the presented value anywhere, which it must not.
     */
    public function holdsPlaintext(string $value): bool
    {
        return array_key_exists($value, $this->rows);
    }
}
