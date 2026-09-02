<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Refresh;

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * A refresh token as it exists for the one moment both halves of it are known.
 *
 * The value goes to the client, once, and is never seen again by this
 * application: what a store keeps is {@see $hash}. That asymmetry is the whole
 * point — a leaked database of refresh tokens is then a leaked database of
 * hashes, which buys an attacker nothing, and a store that persisted `$value`
 * would have thrown that away.
 *
 * The hash is derived rather than passed, so the two halves cannot be handed
 * in disagreeing: a token whose `hash` is not `hashOf($value)` would be stored
 * under a key no presentation of it will ever produce, and would fail as
 * "nobody was ever issued this" long after the mistake.
 *
 * Not a JWT, deliberately. A refresh token is presented to the issuer that
 * minted it and to nobody else, so it needs no self-description, no signature
 * to verify and no claims to read: it is a lookup key, and 256 bits of
 * randomness is a better one than a signed document that cannot be revoked
 * without the same lookup (§8.1 of `docs/plan.md`).
 */
final class RefreshToken
{
    /** What a store persists in place of {@see $value}. */
    public readonly string $hash;

    /**
     * @param string            $value     the opaque token, handed to the client and stored nowhere
     * @param DateTimeImmutable $expiresAt when the token stops being accepted, whatever the store still holds
     */
    public function __construct(
        public readonly string $value,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        $this->hash = self::hashOf($value);
    }

    /**
     * The one place the hashing rule lives, so a generator and a store cannot
     * disagree about it. An implementation of
     * {@see RefreshTokenStoreInterface::consume()} hashes what the client
     * presented with this and looks that up.
     *
     * **SHA-256 rather than a password hash, on purpose.** `password_hash()`
     * is slow because a password is guessable and a human chose it; a refresh
     * token is 256 bits from `random_bytes()`, so there is nothing to guess
     * and the cost buys nothing. It would also be a cost paid on every token
     * refresh, which is a denial-of-service lever pointed at your own login
     * flow. What matters here is that the stored form is not the presented
     * form, and a fast hash over an unguessable input gives exactly that.
     *
     * @throws InvalidArgumentException when `$presented` is empty. Callers reading a token off a
     *                                  request do not have to guard against that themselves:
     *                                  {@see RefreshTokenStoreInterface::consume()} answers `null`
     *                                  for an empty presentation rather than raising
     */
    public static function hashOf(string $presented): string
    {
        if ('' === $presented) {
            throw new InvalidArgumentException('An empty string is not a refresh token, so there is nothing to hash or look up.');
        }

        return hash('sha256', $presented);
    }
}
