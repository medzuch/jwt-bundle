<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Refresh;

use DateTimeImmutable;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * What a store knew about a refresh token, handed back the moment it is spent.
 *
 * Four things, because four things decide what happens next: who it was minted
 * for, whether it is still inside its lifetime, whether somebody has already
 * spent it, and — for an application that models one — which grant it descends
 * from.
 *
 * {@see $alreadyUsed} is the reason this type exists rather than
 * {@see RefreshTokenStoreInterface::consume()} simply answering yes or no. A
 * token presented twice is not the same event as a token nobody recognises: an
 * unknown string is noise, while a *second* use of a real token means either
 * the client retried or somebody else is holding a copy. Neither the store nor
 * this bundle can tell which, and the caller usually cannot either — which is
 * why RFC 9700 §4.14.2 treats the ambiguity as the signal and revokes rather
 * than investigating.
 *
 * **Read the expiry before reading `alreadyUsed`.** A token that had already
 * expired when it was presented says nothing about theft, and a store spending
 * the row anyway means the client's retry of that same dead token would
 * otherwise look like a replay. {@see isUsable()} is the order written down.
 */
final class RefreshTokenRecord
{
    /**
     * @param string            $subject     whoever the token was minted for — the identifier your user provider loads
     * @param DateTimeImmutable $expiresAt   the moment it stops being accepted
     * @param bool              $alreadyUsed true when the store had already spent this token before this call
     * @param string|null       $grant       the lineage this token descends from, for a store that keeps one;
     *                                       `null` where an application does not model grants
     */
    public function __construct(
        public readonly string $subject,
        public readonly DateTimeImmutable $expiresAt,
        public readonly bool $alreadyUsed = false,
        public readonly ?string $grant = null,
    ) {
        if ('' === $subject) {
            throw new InvalidArgumentException('A refresh token record names the subject it was minted for; an empty one identifies nobody to issue the next token to.');
        }

        if ('' === $grant) {
            throw new InvalidArgumentException('A grant is either named or absent; an empty string is a lineage nothing can be revoked by. Pass null where an application does not model grants.');
        }
    }

    /**
     * Read from a clock rather than `new DateTimeImmutable()` so the same
     * question is answerable in a test that does not wait.
     */
    public function isExpired(ClockInterface|DateTimeImmutable $now): bool
    {
        $moment = $now instanceof ClockInterface ? $now->now() : $now;

        return $this->expiresAt <= $moment;
    }

    /**
     * The one condition under which the caller may mint the next access token:
     * a token this store knew, spent for the first time, still inside its
     * lifetime.
     *
     * The two failing cases mean different things and are worth separating in
     * the caller. An expired token is a session that ran out; a spent one is
     * either a retry or a theft, and {@see $alreadyUsed} is only worth reacting
     * to when the token had not already expired.
     */
    public function isUsable(ClockInterface|DateTimeImmutable $now): bool
    {
        return !$this->alreadyUsed && !$this->isExpired($now);
    }
}
