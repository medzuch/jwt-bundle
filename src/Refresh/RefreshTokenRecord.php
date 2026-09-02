<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Refresh;

use DateTimeImmutable;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * What a store knew about a refresh token, handed back the moment it is spent.
 *
 * Three things, because three things decide what happens next: who it was
 * minted for, whether it is still inside its lifetime, and whether somebody
 * has already spent it.
 *
 * That last one is the reason this type exists rather than
 * {@see RefreshTokenStoreInterface::consume()} simply answering yes or no. A
 * token presented twice is not the same event as a token nobody recognises: an
 * unknown string is noise, while a *second* use of a real token means either
 * the client retried or somebody else is holding a copy — and neither the
 * store nor this bundle can tell which. The caller can, or can decide it does
 * not need to and revoke the family either way (OAuth 2.1 §6.1 asks for
 * exactly that).
 */
final class RefreshTokenRecord
{
    /**
     * @param string            $subject     whoever the token was minted for — the identifier your user provider loads
     * @param DateTimeImmutable $expiresAt   the moment it stops being accepted
     * @param bool              $alreadyUsed true when the store had already spent this token before this call
     */
    public function __construct(
        public readonly string $subject,
        public readonly DateTimeImmutable $expiresAt,
        public readonly bool $alreadyUsed = false,
    ) {
        if ('' === $subject) {
            throw new InvalidArgumentException('A refresh token record names the subject it was minted for; an empty one identifies nobody to issue the next token to.');
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
     * lifetime. Anything else is a refusal, and the two failing cases mean
     * different things — {@see $alreadyUsed} is the one worth reacting to.
     */
    public function isUsable(ClockInterface|DateTimeImmutable $now): bool
    {
        return !$this->alreadyUsed && !$this->isExpired($now);
    }
}
