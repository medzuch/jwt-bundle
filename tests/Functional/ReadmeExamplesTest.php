<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Yaml\Yaml;

/**
 * Every `medzuch_jwt` example in the README is compiled into a real container.
 *
 * Documentation that is only read goes stale silently; a configuration key
 * renamed in the tree would leave the quickstart telling newcomers to write
 * something that no longer boots. Here it fails the suite instead.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class ReadmeExamplesTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    /**
     * @param array<string, mixed> $configuration
     */
    #[DataProvider('readmeConfigurations')]
    #[TestDox('the README example on line $line compiles')]
    public function testReadmeExampleCompiles(int $line, array $configuration): void
    {
        self::bootKernel(['medzuch_jwt' => $configuration]);

        self::assertTrue(self::getContainer()->has('medzuch_jwt.clock'));
    }

    /**
     * @return iterable<string, array{int, array<string, mixed>}>
     */
    public static function readmeConfigurations(): iterable
    {
        $readme = file_get_contents(__DIR__ . '/../../README.md');
        self::assertIsString($readme);

        preg_match_all('/```yaml\n(.*?)```/s', $readme, $matches, \PREG_OFFSET_CAPTURE);

        $found = 0;

        foreach ($matches[1] as $match) {
            [$snippet, $offset] = $match;
            $parsed = Yaml::parse($snippet);

            if (!is_array($parsed) || !isset($parsed['medzuch_jwt']) || !is_array($parsed['medzuch_jwt'])) {
                continue;
            }

            ++$found;
            $line = substr_count(substr($readme, 0, $offset), "\n") + 1;

            /** @var array<string, mixed> $configuration */
            $configuration = $parsed['medzuch_jwt'];

            yield sprintf('README line %d', $line) => [$line, $configuration];
        }

        self::assertGreaterThan(0, $found, 'the README should carry at least one medzuch_jwt example');
    }
}
