<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Size and modification time of everything a test container is compiled from,
 * hashed once per process.
 *
 * A compiled container tracks the *configuration files* it was built from and
 * rebuilds when one changes; a PHP class is not one of them. So editing an
 * extension, a compiler pass or a kernel and re-running reuses the container
 * the previous edit produced — and in the unhelpful direction. Warming the
 * cache on correct code and then breaking it rebuilds, because a tracked file
 * moved; warming it on broken code and then fixing it does not, and that is
 * the order someone works in. CI never notices, since every run starts with an
 * empty directory, so what it produces is a local-only false green.
 *
 * Every kernel here keys its cache directory on this, and every kernel has the
 * same reason to: `SecuredKernel` is the one that exercises the firewall
 * round-trip.
 *
 * Contents would be exact and would mean reading the whole package on every
 * boot; a file whose bytes change while its size and modification time do not
 * is not something an editor, a checkout or a patch produces.
 */
final class SourceFingerprint
{
    /**
     * Where a service in a test container comes from: the package, the
     * configuration it ships, and the test application's own classes.
     */
    private const COMPILED_FROM = ['src', 'config', 'tests/Functional/App'];

    public static function current(): string
    {
        static $fingerprint = null;

        if (null !== $fingerprint) {
            return $fingerprint;
        }

        $root = dirname(__DIR__, 3);
        $stamps = [];

        foreach (self::COMPILED_FROM as $directory) {
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root . '/' . $directory, FilesystemIterator::SKIP_DOTS),
            );

            foreach ($files as $file) {
                if (!$file instanceof SplFileInfo || !$file->isFile()) {
                    continue;
                }

                // Relative to the package root, so two checkouts of the same
                // commit fingerprint alike rather than by where they sit.
                $path = substr($file->getPathname(), strlen($root) + 1);

                $stamps[$path] = [$file->getSize(), $file->getMTime()];
            }
        }

        ksort($stamps);

        return $fingerprint = hash('xxh128', serialize($stamps));
    }
}
