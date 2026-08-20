<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache that keeps what it was given and, unlike a real one, admits
 * what TTL it was given with — which is the only way to assert that the
 * configured lifetime reached the resolver rather than its default.
 *
 * Expiry is not implemented: nothing here outlives one test, and a cache that
 * silently dropped an entry would make a fetch count mean two things.
 */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    private array $values = [];

    /** @var array<string, int|DateInterval|null> */
    public array $ttls = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    public function set(string $key, mixed $value, int|DateInterval|null $ttl = null): bool
    {
        $this->values[$key] = $value;
        $this->ttls[$key] = $ttl;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key], $this->ttls[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->values = [];
        $this->ttls = [];

        return true;
    }

    /**
     * @param iterable<mixed, string> $keys
     *
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->get($key, $default);
        }
    }

    /**
     * @param iterable<mixed, mixed> $values
     */
    public function setMultiple(iterable $values, int|DateInterval|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            \assert(is_string($key) || is_int($key));

            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    /**
     * @param iterable<mixed, string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }
}
