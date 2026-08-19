<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Holds the README to the bundle.
 *
 * Documentation that is only read goes stale quietly: a renamed configuration
 * key or service id would leave the quickstart telling newcomers to write
 * something that no longer works. So every `medzuch_jwt` example is compiled
 * into a real container, and every service id the README tells people to paste
 * into `security.yaml` has to exist in one of them.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class ReadmeExamplesTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    /** The README names a Monolog channel, which an application provides. */
    private const APPLICATION_SERVICES = ['monolog.logger.jwt' => 'test.logger'];

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : [], self::APPLICATION_SERVICES);
    }

    /**
     * @param array<string, mixed> $configuration
     */
    #[DataProvider('readmeConfigurations')]
    #[TestDox('the README example on line $line compiles, with the services it advertises')]
    public function testReadmeExampleCompiles(int $line, array $configuration): void
    {
        self::bootKernel(['medzuch_jwt' => $configuration]);

        $container = self::getContainer();

        foreach (self::advertisedServices($configuration) as $id) {
            self::assertTrue($container->has($id), sprintf('README line %d implies the service "%s"', $line, $id));
        }
    }

    #[TestDox('every medzuch_jwt service id the README mentions is a service some example builds')]
    public function testMentionedServiceIdsExist(): void
    {
        $available = [];

        foreach (self::readmeConfigurations() as [, $configuration]) {
            $available = [...$available, ...self::advertisedServices($configuration)];
        }

        preg_match_all('/\bmedzuch_jwt\.[a-z0-9_]+\.[a-z0-9_]+\b/', self::readme(), $matches);

        $mentioned = array_unique($matches[0]);
        self::assertNotSame([], $mentioned, 'the README should name at least one service id');

        foreach ($mentioned as $id) {
            self::assertContains($id, $available, sprintf('the README tells the reader to use "%s"', $id));
        }
    }

    /**
     * Service ids an example promises by declaring the sections it declares.
     *
     * @param array<string, mixed> $configuration
     *
     * @return list<string>
     */
    private static function advertisedServices(array $configuration): array
    {
        $ids = [];

        foreach (['consumers' => ['consumer', 'handler'], 'issuers' => ['issuer', 'login']] as $section => $prefixes) {
            $entries = $configuration[$section] ?? [];

            if (!is_array($entries)) {
                continue;
            }

            foreach (array_keys($entries) as $name) {
                foreach ($prefixes as $prefix) {
                    $ids[] = sprintf('medzuch_jwt.%s.%s', $prefix, $name);
                }
            }
        }

        // A key entry advertises the halves it actually carries: a public-only
        // entry can verify and not sign, and there is no signing service to
        // expect from it.
        $keys = $configuration['keys'] ?? [];

        if (is_array($keys)) {
            foreach ($keys as $name => $key) {
                if (!is_array($key)) {
                    continue;
                }

                if (isset($key['hmac']) || isset($key['pem_private'])) {
                    $ids[] = sprintf('medzuch_jwt.key.%s', $name);
                }

                if (isset($key['hmac']) || isset($key['pem_public'])) {
                    $ids[] = sprintf('medzuch_jwt.key.%s.verification', $name);
                }
            }
        }

        return $ids;
    }

    /**
     * @return iterable<string, array{int, array<string, mixed>}>
     */
    public static function readmeConfigurations(): iterable
    {
        $readme = self::readme();

        preg_match_all('/```yaml\n(.*?)```/s', $readme, $matches, \PREG_OFFSET_CAPTURE);

        $found = 0;

        foreach ($matches[1] as $match) {
            [$snippet, $offset] = $match;
            $line = substr_count(substr($readme, 0, $offset), "\n") + 1;

            try {
                $parsed = Yaml::parse($snippet);
            } catch (ParseException $e) {
                throw new RuntimeException(sprintf('README line %d is not parsable YAML: %s', $line, $e->getMessage()), 0, $e);
            }

            if (!is_array($parsed) || !isset($parsed['medzuch_jwt']) || !is_array($parsed['medzuch_jwt'])) {
                continue;
            }

            ++$found;

            /** @var array<string, mixed> $configuration */
            $configuration = $parsed['medzuch_jwt'];

            yield sprintf('README line %d', $line) => [$line, $configuration];
        }

        if (0 === $found) {
            throw new RuntimeException('the README carries no medzuch_jwt examples; it used to');
        }
    }

    private static function readme(): string
    {
        $readme = file_get_contents(__DIR__ . '/../../README.md');

        if (false === $readme) {
            throw new RuntimeException('README.md is unreadable');
        }

        return $readme;
    }
}
