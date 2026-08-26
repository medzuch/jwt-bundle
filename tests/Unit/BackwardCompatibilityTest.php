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
        $declarations = [...self::sourceClasses(internal: true), ...self::sourceClasses(internal: false)];
        $seen = 0;

        foreach ($declarations as $class) {
            ++$seen;

            if (!self::isAClass($class)) {
                continue;
            }

            self::assertTrue((new ReflectionClass($class))->isFinal(), $class . ' should be final');
        }

        // Every declaration was considered — a floor would pass a sweep that
        // silently stopped seeing half of `src/`.
        self::assertCount($seen, $declarations, 'the sweep should reach every declaration in src');
        self::assertCount(count(self::sources()), $declarations, 'src should hold one declaration per file');
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
     * The regex *is* the table's format: a first cell that is one backticked
     * name relative to this package's namespace. A row aligned with extra
     * spaces, or written with a leading `Medzuch\JwtBundle\`, would not match
     * — so the rows are counted as well as read, and a row that stops looking
     * like a row fails rather than disappearing.
     *
     * @return list<string>
     */
    private static function promised(): array
    {
        $table = self::classTable();

        preg_match_all('/^\| `([A-Z][A-Za-z0-9\\\\]*)` \|/m', $table, $matches);

        $rows = preg_split('/\R/', trim($table));

        self::assertIsArray($rows);

        // Every line of the slice except the heading and the separator beneath
        // it is a promise, and every promise has to have been read.
        self::assertCount(count($rows) - 2, $matches[1], 'a row of the class table is written in a shape the test does not read');

        return array_values(array_unique(array_map(
            static fn(string $name): string => self::NAMESPACE . $name,
            $matches[1],
        )));
    }

    /**
     * The class table, from its heading to the blank line that ends it.
     */
    private static function classTable(): string
    {
        $policy = self::policy();
        $heading = '| | Use it | Call it | Extend it | Implement it |';
        $start = strpos($policy, $heading);

        if (false === $start) {
            throw new RuntimeException('BACKWARD-COMPATIBILITY.md has no class table');
        }

        $end = strpos($policy, "\n\n", $start);

        return substr($policy, $start, false === $end ? null : $end - $start);
    }

    /**
     * Classes under `src/`, by whether their own docblock says `@internal`.
     *
     * @return list<string>
     */
    private static function sourceClasses(bool $internal): array
    {
        $found = [];

        foreach (self::sources() as $file) {
            $source = (string) file_get_contents($file->getPathname());

            if (1 !== preg_match('/^namespace ([^;]+);/m', $source, $namespace)) {
                continue;
            }

            // Every declaration, not the first: a second type in one file would
            // otherwise be neither promised nor disclaimed and pass anyway.
            preg_match_all('/^(?:final |abstract |readonly )*(?:class|interface|enum|trait) (\w+)/m', $source, $declarations, \PREG_OFFSET_CAPTURE | \PREG_SET_ORDER);

            foreach ($declarations as $declaration) {
                if (self::saysInternal($source, $declaration[0][1]) === $internal) {
                    $found[] = $namespace[1] . '\\' . $declaration[1][0];
                }
            }
        }

        sort($found);

        return $found;
    }

    /**
     * Whether the declaration at this offset carries `@internal` of its own.
     *
     * The docblock has to be the one immediately above it — attributes may sit
     * between, nothing else. A class written with no docblock at all would
     * otherwise inherit the previous one in the file, `@internal` included, and
     * be disclaimed by a comment about something else.
     *
     * The tag has to be on a line of its own, too. A docblock that *mentions*
     * the tag — a public class pointing at the internal ones beside it — is
     * describing its neighbours, not disclaiming itself, and reading that as a
     * disclaimer would drop a promised class out of the policy silently.
     */
    private static function saysInternal(string $source, int $offset): bool
    {
        $head = rtrim(substr($source, 0, $offset));

        // Attributes, which may be several lines and may hold anything.
        while (str_ends_with($head, ')]') || str_ends_with($head, ']')) {
            $head = rtrim(substr($head, 0, (int) strrpos($head, '#[')));
        }

        if (!str_ends_with($head, '*/')) {
            return false;
        }

        $opens = strrpos($head, '/**');

        return false !== $opens
            && 1 === preg_match('~^\s*\*\s*@internal\b~m', substr($head, $opens));
    }

    /**
     * @return list<\SplFileInfo>
     */
    private static function sources(): array
    {
        /** @var iterable<array-key, \SplFileInfo> $files */
        $files = new \RegexIterator(
            new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__ . '/../../src')),
            '/\.php$/',
        );

        return array_values(iterator_to_array($files));
    }

    #[TestDox('the supported versions the policy states are the ones composer requires')]
    public function testSupportedVersionsMatchComposer(): void
    {
        $composer = json_decode((string) file_get_contents(__DIR__ . '/../../composer.json'), true, 512, \JSON_THROW_ON_ERROR);

        self::assertIsArray($composer);
        self::assertArrayHasKey('require', $composer);
        self::assertIsArray($composer['require']);

        $policy = self::policy();

        foreach (['php', 'symfony/security-bundle', 'medzuch/jwt-php'] as $package) {
            self::assertArrayHasKey($package, $composer['require']);

            $constraint = $composer['require'][$package];

            self::assertIsString($constraint);
            self::assertStringContainsString(
                '`' . $constraint . '`',
                $policy,
                sprintf('the policy states a support window; composer requires %s %s', $package, $constraint),
            );
        }
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
