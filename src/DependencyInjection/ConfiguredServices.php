<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

/**
 * What the configuration named, between the extension that read it and the
 * pass that checks it.
 *
 * The two run at opposite ends of a container build: `build()` registers the
 * pass before any extension has been read, so there is nothing to hand its
 * constructor at that moment, and `loadExtension()` has the answer long after.
 * They are methods on one bundle object, so the smallest channel between them
 * is an object the bundle holds and the pass was given.
 *
 * A container parameter would be the other way, and was: it puts an `%env()%`
 * inside a parameter, which Symfony refuses outright as an incompatible use of
 * a dynamic environment variable — and it has to be removed again, or the
 * check shows up in every application's `debug:container`.
 *
 * @internal
 */
final class ConfiguredServices
{
    /**
     * @var array<string, array{id: string, hint: string|null}>
     */
    private array $named = [];

    /**
     * @param array<string, array{id: string, hint: string|null}> $named
     */
    public function record(array $named): void
    {
        $this->named = $named;
    }

    /**
     * @return array<string, array{id: string, hint: string|null}>
     */
    public function all(): array
    {
        return $this->named;
    }
}
