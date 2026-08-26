<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Holds the pointers `src/` makes at the documentation.
 *
 * CONTRIBUTING's comment charter asks a docblock to name a README heading
 * rather than paste what it says, and a decision to be a `DEC-n` in the plan.
 * Both are pointers, and a pointer nothing checks is how the pasted copy comes
 * back: the heading gets reworded, the comment keeps citing the old one, and
 * nothing anywhere goes red.
 *
 * So the citation format is the assertion. `README "Some heading"` has to name
 * a heading the README actually carries, and `DEC-n` has to be a decision
 * `docs/plan.md` records.
 */
#[CoversNothing]
final class DocumentationPointersTest extends TestCase
{
    /** `dirname()` rather than `__DIR__ . '/../..'`: the iterator below reports
     * canonical pathnames, and a prefix carrying `..` would not strip off them. */
    private static function root(): string
    {
        return dirname(__DIR__, 2);
    }

    #[TestDox('every README heading a comment in src cites is a heading the README has')]
    public function testCitedHeadingsExist(): void
    {
        $headings = self::readmeHeadings();

        self::assertNotSame([], $headings, 'the README should carry headings to cite');

        $cited = 0;

        foreach (self::sources() as $file => $source) {
            // The charter's format, spelled the way the charter spells it. A
            // comment citing the README any other way is invisible here, which
            // is the reason the count below is asserted too.
            preg_match_all('/README "([^"]+)"/', self::withoutLineBreaks($source), $matches);

            foreach (array_unique($matches[1]) as $heading) {
                self::assertContains(
                    $heading,
                    $headings,
                    sprintf('%s points at README "%s", which is not a heading there', $file, $heading),
                );

                ++$cited;
            }
        }

        self::assertGreaterThan(5, $cited, 'src should be citing README headings; the charter asks for it');
    }

    #[TestDox('every DEC a comment in src cites is one the plan records')]
    public function testCitedDecisionsExist(): void
    {
        $plan = self::read('docs/plan.md');

        preg_match_all('/^\*\*DEC-(\d+) —/m', $plan, $recorded);

        self::assertNotSame([], $recorded[1], 'the plan should record decisions to cite');

        $cited = 0;

        foreach (self::sources() as $file => $source) {
            preg_match_all('/\bDEC-(\d+)\b/', $source, $matches);

            foreach (array_unique($matches[1]) as $number) {
                self::assertContains(
                    $number,
                    $recorded[1],
                    sprintf('%s cites DEC-%s, which docs/plan.md §9 does not record', $file, $number),
                );

                ++$cited;
            }
        }

        self::assertGreaterThan(1, $cited, 'src should be citing decisions by number');
    }

    /**
     * A citation may be wrapped across two comment lines, so the leading `*` of
     * a continuation and the newline itself collapse to one space before the
     * heading is matched.
     */
    private static function withoutLineBreaks(string $source): string
    {
        return (string) preg_replace('~\s*\n\s*\*\s*~', ' ', $source);
    }

    /**
     * @return list<string>
     */
    private static function readmeHeadings(): array
    {
        preg_match_all('/^#{2,4} (.+)$/m', self::read('README.md'), $matches);

        return array_map(trim(...), $matches[1]);
    }

    /**
     * @return array<string, string>
     */
    private static function sources(): array
    {
        $found = [];
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::root() . '/src'));

        foreach ($files as $file) {
            if (!$file instanceof \SplFileInfo || 'php' !== $file->getExtension()) {
                continue;
            }

            $path = (string) $file->getPathname();
            $contents = file_get_contents($path);

            if (false === $contents) {
                throw new RuntimeException($path . ' should be readable');
            }

            // Keyed by the path a failure message should name, not by basename:
            // two `KeyLoader.php` in different directories would collapse.
            $found[substr($path, strlen(self::root()) + 1)] = $contents;
        }

        self::assertNotSame([], $found, 'src should hold PHP files');

        return $found;
    }

    private static function read(string $path): string
    {
        $full = self::root() . '/' . $path;
        $contents = file_get_contents($full);

        if (false === $contents) {
            throw new RuntimeException($path . ' should be readable');
        }

        return $contents;
    }
}
