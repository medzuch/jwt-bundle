<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Revocation;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * A denylist in a PSR-16 cache, where an entry expires with the token it
 * refuses.
 *
 * The store this asks for is the one whose semantics match the data: an entry
 * that must outlive one token and no longer is exactly `set($key, true, $ttl)`,
 * and a cache does the forgetting itself. A relational table would need a
 * schema, a migration and something to sweep it (DEC-3).
 *
 * What it gives up is durability: flush the cache and every revocation is
 * forgotten, while the tokens they refused are still valid. For a deployment
 * that cannot accept that, the interface is the extension point — an
 * application-owned implementation over its own store, named under
 * `denylist.service`.
 */
final class CacheTokenDenylist implements TokenDenylistInterface
{
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly string $prefix,
    ) {}

    public function revoke(string $jti, DateTimeImmutable $until): void
    {
        $ttl = $until->getTimestamp() - $this->clock->now()->getTimestamp();

        // Already expired: the token is refused on its own `exp`, and an entry
        // with a non-positive TTL is one PSR-16 deletes or refuses outright.
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
     */
    private function key(string $jti): string
    {
        return $this->prefix . hash('xxh128', $jti);
    }
}
