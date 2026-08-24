<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use RuntimeException;

/**
 * Holds the backward-compatibility policy to the code it describes.
 *
 * A policy document is a promise about every class in `src/`, and a promise
 * nothing checks is one that a new file quietly breaks: a class added without a
 * thought about which side of the line it is on is neither promised nor
 * disclaimed, and the answer to "is this public?" becomes whatever the reader
 * assumes. So the table in `BACKWARD-COMPATIBILITY.md` is read back here and
 * compared to what `src/` actually marks `@internal`, in both directions.
 *
 * `@internal` on a method is not read: {@see \Medzuch\JwtBundle\DataCollector\JwtDataCollector}
 * is public to read and internal to write, which is a distinction only its
 * docblocks can make.
 */
#[CoversNothing]
final class BackwardCompatibilityTest extends TestCase
{
    private const POLICY = __DIR__ . '/../../BACKWARD-COMPATIBILITY.md';

    private const NAMESPACE = 'Medzuch\\JwtBundle\\';

    #[TestDox('every class in src is either promised by the policy or marked @internal')]
    public function testEveryClassPicksASide(): void
    {
        $promised = self::promised();
        $public = self::sourceClasses(internal: false);

        self::assertNotSame([], $promised, 'the policy should promise at least one class');

        foreach ($public as $class) {
            self::assertContains($class, $promised, sprintf('%s is not marked @internal, so the policy has to promise it', $class));
        }

        foreach ($promised as $class) {
            self::assertContains($class, $public, sprintf('the policy promises %s, which is either gone or marked @internal', $class));
        }
    }

    #[TestDox('a class the policy promises exists, and is one nobody can extend')]
    public function testPromisedClassesCannotBeExtended(): void
    {
        foreach (self::promised() as $class) {
            $declared = class_exists($class) || interface_exists($class) || trait_exists($class) || enum_exists($class);

            self::assertTrue($declared, sprintf('the policy promises %s, which does not exist', $class));

            if (!self::isAClass($class)) {
                // An interface or a trait: "extend it" is not the question the
                // policy answers for those rows.
                continue;
            }

            self::assertTrue((new ReflectionClass($class))->isFinal(), sprintf('the policy says every class is final, and %s is not', $class));
        }
    }

    #[TestDox('every class in src is final, whichever side of the line it is on')]
    public function testEveryClassIsFinal(): void
    {
        $checked = 0;

        foreach ([...self::sourceClasses(internal: true), ...self::sourceClasses(internal: false)] as $class) {
            if (!self::isAClass($class)) {
                continue;
            }

            self::assertTrue((new ReflectionClass($class))->isFinal(), $class . ' should be final');

            ++$checked;
        }

        self::assertGreaterThan(30, $checked, 'the sweep should reach the classes in src');
    }

    /**
     * Whether the name is a class in the sense `final` applies to.
     *
     * `class_exists()` is false for an interface and for a trait, and an enum is
     * a class that is already final and cannot be declared otherwise — so none
     * of the three is a row where "extend it" has an answer to enforce.
     *
     * @phpstan-assert-if-true class-string $name
     */
    private static function isAClass(string $name): bool
    {
        return class_exists($name) && !(new ReflectionClass($name))->isEnum();
    }

    /**
     * The class names the policy's table promises, as fully-qualified names.
     *
     * Only the first cell of a row is read, and only when it is a backticked
     * name starting with a capital: the service-id table beside it is rows of
     * lowercase ids, and the header and separator rows have no first cell at
     * all.
     *
     * @return list<string>
     */
    private static function promised(): array
    {
        preg_match_all('/^\| `([A-Z][A-Za-z0-9\\\\]*)` \|/m', self::policy(), $matches);

        return array_values(array_unique(array_map(
            static fn(string $name): string => self::NAMESPACE . $name,
            $matches[1],
        )));
    }

    /**
     * Classes under `src/`, by whether their own docblock says `@internal`.
     *
     * @return list<string>
     */
    private static function sourceClasses(bool $internal): array
    {
        $found = [];

        /** @var iterable<string, \SplFileInfo> $files */
        $files = new \RegexIterator(
            new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__ . '/../../src')),
            '/\.php$/',
        );

        foreach ($files as $file) {
            $source = (string) file_get_contents($file->getPathname());

            if (1 !== preg_match('/^namespace ([^;]+);/m', $source, $namespace)) {
                continue;
            }

            if (1 !== preg_match('/^(?:final |abstract |readonly )*(?:class|interface|enum|trait) (\w+)/m', $source, $declaration)) {
                continue;
            }

            // The docblock immediately before the declaration, which is the
            // only one that says anything about the class itself.
            $head = substr($source, 0, (int) strpos($source, $declaration[0]));
            $block = str_contains($head, '/**') ? substr($head, (int) strrpos($head, '/**')) : '';

            if (str_contains($block, '@internal') === $internal) {
                $found[] = $namespace[1] . '\\' . $declaration[1];
            }
        }

        sort($found);

        return $found;
    }

    private static function policy(): string
    {
        $policy = file_get_contents(self::POLICY);

        if (false === $policy) {
            throw new RuntimeException('BACKWARD-COMPATIBILITY.md is unreadable');
        }

        return $policy;
    }
}
