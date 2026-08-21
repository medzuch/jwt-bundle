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

    /**
     * Service ids the README names because an application has them: a Monolog
     * channel, Symfony's PSR-18 client, and the default cache pool.
     */
    private const APPLICATION_SERVICES = [
        'monolog.logger.jwt' => 'test.logger',
        'psr18.http_client' => 'test.http_client',
        'cache.app' => 'test.cache_pool',
    ];

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

    #[TestDox('an autowired argument in a PHP example names a registration the README declares')]
    public function testAutowiredArgumentNamesMatchRegistrations(): void
    {
        // The YAML blocks are compiled; the PHP beside them is not, so an
        // argument name that matches no registration reads as working code and
        // is a container error on first boot. This is the narrow invariant that
        // catches it: the name in `IdTokenVerifier $x` is the registration
        // name, so `x` has to be one the README configures.
        $declared = [];

        foreach (self::readmeConfigurations() as [, $configuration]) {
            $registrations = $configuration['id_tokens'] ?? [];

            if (is_array($registrations)) {
                $declared = [...$declared, ...array_keys($registrations)];
            }
        }

        self::assertNotSame([], $declared, 'the README should configure at least one id_tokens registration');

        preg_match_all('/IdTokenVerifier \$(\w+)/', self::readme(), $matches);

        self::assertNotSame([], $matches[1], 'the README should show the verifier being injected');

        foreach (array_unique($matches[1]) as $argument) {
            self::assertContains($argument, $declared, sprintf('the README injects "IdTokenVerifier $%s", which no example registers', $argument));
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

        // A consumer promises a denylist service only when it configures one:
        // unconfigured, there is nothing in the container to name.
        $consumers = $configuration['consumers'] ?? [];

        if (is_array($consumers)) {
            foreach ($consumers as $consumer => $entry) {
                if (is_array($entry) && [] !== ($entry['denylist'] ?? [])) {
                    $ids[] = sprintf('medzuch_jwt.denylist.%s', $consumer);
                }
            }
        }

        $extractors = $configuration['token_extractors'] ?? [];

        if (is_array($extractors)) {
            foreach (array_keys($extractors) as $extractor) {
                $ids[] = sprintf('medzuch_jwt.token_extractor.%s', $extractor);
            }
        }

        $registrations = $configuration['id_tokens'] ?? [];

        if (is_array($registrations)) {
            foreach (array_keys($registrations) as $registration) {
                $ids[] = sprintf('medzuch_jwt.id_token.%s', $registration);
            }
        }

        $sets = $configuration['remote_jwks'] ?? [];

        if (is_array($sets)) {
            foreach (array_keys($sets) as $set) {
                $ids[] = sprintf('medzuch_jwt.remote_jwks.%s', $set);
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

                if (isset($key['hmac']) || isset($key['pem_private']) || isset($key['jwk_private'])) {
                    $ids[] = sprintf('medzuch_jwt.key.%s', $name);
                    $ids[] = sprintf('medzuch_jwt.key.%s.signing', $name);
                }

                if (isset($key['hmac']) || isset($key['pem_public']) || isset($key['jwk_public'])) {
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
