<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use DateInterval;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

/**
 * A PSR-16 cache that is down.
 *
 * Every read and write throws, which is what a Redis nobody can reach does
 * through most adapters. It exists to assert which way a revocation check fails
 * when the store it depends on is unavailable — the answer being "closed", and
 * the point being that it is asserted rather than assumed.
 */
final class ThrowingCache implements CacheInterface
{
    public const MESSAGE = 'the cache is down';

    public function get(string $key, mixed $default = null): mixed
    {
        throw new RuntimeException(self::MESSAGE);
    }

    public function set(string $key, mixed $value, int|DateInterval|null $ttl = null): bool
    {
        throw new RuntimeException(self::MESSAGE);
    }

    public function delete(string $key): bool
    {
        throw new RuntimeException(self::MESSAGE);
    }

    public function clear(): bool
    {
        throw new RuntimeException(self::MESSAGE);
    }

    /**
     * @param iterable<mixed, string> $keys
     *
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        throw new RuntimeException(self::MESSAGE);
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, int|DateInterval|null $ttl = null): bool
    {
        throw new RuntimeException(self::MESSAGE);
    }

    /**
     * @param iterable<mixed, string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        throw new RuntimeException(self::MESSAGE);
    }

    public function has(string $key): bool
    {
        throw new RuntimeException(self::MESSAGE);
    }
}
