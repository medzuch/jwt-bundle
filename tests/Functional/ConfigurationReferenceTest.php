<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\DependencyInjection\ConfigurationTree;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Holds the configuration reference `config:dump-reference` prints.
 *
 * Not the option *names*, which turned out to be covered already: all fifty-nine of
 * them are configured by the documentation or by a functional test, so renaming
 * one already reddens something. `BACKWARD-COMPATIBILITY.md` framed the gap as
 * renames and was wider than the truth.
 *
 * The gap is the printed reference itself — the `info()` strings, the defaults
 * and the examples. Reword one `info()` and the whole suite stays green with
 * this case excluded, which was measured rather than assumed. Those strings are
 * what `config:dump-reference` prints to an application developer, so they are
 * documentation, and this is the only thing holding them.
 *
 * The comparison is exact rather than normalised because the output is byte for
 * byte the same from Symfony 6.4.44 through 8.1.5. It is not the same on 6.4.0:
 * the renderer moved inside the 6.4 line, which is narrower than the majors
 * that were checked, and CI found it on the leg that resolves the true floor.
 */
#[CoversClass(ConfigurationTree::class)]
final class ConfigurationReferenceTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const REFERENCE = __DIR__ . '/../../docs/configuration-reference.md';

    /**
     * The command that refreshes the file, quoted in the failure so that
     * whoever changed the tree deliberately is one paste away from recording
     * it.
     */
    private const REFRESH = 'make config-reference';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new TestKernel();
    }

    #[TestDox('the committed configuration reference is what config:dump-reference prints')]
    public function testReferenceMatchesTheTree(): void
    {
        self::bootKernel();

        $dumped = self::dumped();

        if (!self::rendersLikeTheSnapshot($dumped)) {
            self::markTestSkipped(
                'this Symfony renders config:dump-reference examples in the older shape; '
                . 'what differs is upstream formatting, not the tree this case is about',
            );
        }

        self::assertSame(
            self::committed(),
            $dumped,
            sprintf(
                'docs/configuration-reference.md no longer matches the configuration tree. '
                . 'If the tree changed on purpose, run `%s` to record it; the file is generated.',
                self::REFRESH,
            ),
        );
    }

    /**
     * Whether this Symfony prints the reference the way the snapshot records it.
     *
     * The renderer moved inside 6.4: the newer one prints an empty-list default
     * as `[]` and comments each example item, the older prints neither. So a
     * tree resolved with `--prefer-lowest` disagrees with the snapshot about
     * upstream's formatting and about nothing else, and there is nothing here
     * for that leg to hold — the same reason CI skips PHPStan on it.
     *
     * Detected from the output rather than from a version number, because the
     * patch it changed in is not something to guess at, and the shape is what
     * the comparison actually depends on.
     */
    private static function rendersLikeTheSnapshot(string $dumped): bool
    {
        return 1 !== preg_match('~# Examples:\n\s+- ~', $dumped);
    }

    private static function dumped(): string
    {
        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);

        $application = new Application($kernel);
        $application->setAutoExit(false);

        $tester = new CommandTester($application->find('config:dump-reference'));
        $tester->execute(['name' => 'medzuch_jwt', '--no-debug' => true]);

        return rtrim($tester->getDisplay(), "\n");
    }

    /**
     * The fenced block the document carries, which is the whole of what is
     * compared: the prose around it is free to change.
     */
    private static function committed(): string
    {
        $document = file_get_contents(self::REFERENCE);

        if (false === $document) {
            throw new RuntimeException(self::REFERENCE . ' should be readable');
        }

        if (1 !== preg_match('/```text\n(.*?)\n```/s', $document, $matches)) {
            throw new RuntimeException(sprintf(
                'docs/configuration-reference.md should carry exactly one ```text block; run `%s`',
                self::REFRESH,
            ));
        }

        return $matches[1];
    }
}
