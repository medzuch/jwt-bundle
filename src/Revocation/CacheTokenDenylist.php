<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Revocation;

use DateTimeImmutable;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * A denylist in a PSR-16 cache, where an entry expires with the token it
 * refuses.
 *
 * The store matches the data: an entry that must outlive one token and no
 * longer is exactly `set($key, true, $ttl)`, and a cache forgets on its own
 * where a table would need a schema, a migration and a sweeper (DEC-3).
 *
 * README "Revoking a token" has what that costs — a flush forgets every
 * revocation, and a throwing store takes the request with it as a 500 rather
 * than a 401 — and names the interface as the way out for a deployment that
 * cannot accept either.
 *
 * @internal
 */
final class CacheTokenDenylist implements TokenDenylistInterface
{
    /**
     * @param int $leeway the consumer's clock-skew tolerance, in seconds
     */
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly string $prefix,
        private readonly int $leeway = 0,
    ) {}

    public function revoke(string $jti, DateTimeImmutable $until): void
    {
        if ('' === $jti) {
            throw new InvalidArgumentException('A token id cannot be the empty string; there would be nothing to refuse.');
        }

        // Padded by the leeway, because the consumer accepts a token until
        // `exp` *plus* its tolerance: an entry expiring at `exp` on the dot
        // would leave the revoked token working for exactly the interval
        // leeway exists to forgive.
        $ttl = $until->getTimestamp() - $this->clock->now()->getTimestamp() + $this->leeway;

        // Already past accepting: the token is refused on its own terms, and an
        // entry with a non-positive TTL is one PSR-16 deletes or refuses.
        if ($ttl < 1) {
            return;
        }

        $this->cache->set($this->key($jti), true, $ttl);
    }

    public function isRevoked(string $jti): bool
    {
        return true === $this->cache->get($this->key($jti));
    }

    /**
     * A `jti` is whatever the issuer chose to put there, and PSR-16 §6 reserves
     * `{}()/\@:` in keys and allows a store to cap their length. Hashing takes
     * both questions away, and a denylist has no use for a readable key.
     *
     * `xxh128` is fast rather than collision-resistant, which is the right
     * trade here because of which way a collision fails: two ids landing on one
     * key would refuse an unrelated token, never let a revoked one through. A
     * denylist that is occasionally too strict is a denylist; one that can be
     * steered into letting a token through is not.
     */
    private function key(string $jti): string
    {
        return $this->prefix . hash('xxh128', $jti);
    }
}
