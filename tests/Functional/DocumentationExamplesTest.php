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
 * Holds the documentation to the bundle.
 *
 * Documentation that is only read goes stale quietly: a renamed configuration
 * key or service id would leave the quickstart telling newcomers to write
 * something that no longer works. So every `medzuch_jwt` example is compiled
 * into a real container, and every service id the documentation tells people to
 * paste into `security.yaml` has to exist in one of them.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class DocumentationExamplesTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    /**
     * Documents scanned for service ids they tell the reader to use.
     */
    private const DOCUMENTS = ['README.md', 'docs/cookbook.md', 'UPGRADE.md'];

    /**
     * Documents whose job is to show a configuration that works, so each has to
     * carry at least one. `UPGRADE.md` is not one of them: its YAML is
     * deliberately `diff` rather than `yaml`, because the half being migrated
     * away from is configuration that no longer compiles — which is the point
     * of showing it.
     */
    private const TEACH_CONFIGURATION = ['README.md', 'docs/cookbook.md'];

    /**
     * Service ids the documentation names because an application has them: a Monolog
     * channel, Symfony's PSR-18 client, the default cache pool, and the user
     * factory a `user.mode: custom` recipe tells the reader to write.
     */
    private const APPLICATION_SERVICES = [
        'monolog.logger.jwt' => 'test.logger',
        'psr18.http_client' => 'test.http_client',
        'cache.app' => 'test.cache_pool',
        'App\\Security\\TenantUserFactory' => 'test.user_factory',
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
    #[DataProvider('documentedConfigurations')]
    #[TestDox('the example at $where compiles, with the services it advertises')]
    public function testDocumentedExampleCompiles(string $where, array $configuration): void
    {
        self::bootKernel(['medzuch_jwt' => $configuration]);

        $container = self::getContainer();

        // True of every example, and the reason this case is not risky when a
        // snippet advertises no services of its own — a configuration block
        // that compiles is the assertion, and the clock is what proves the
        // bundle's extension ran at all.
        self::assertTrue($container->has('medzuch_jwt.clock'), sprintf('%s should compile the bundle', $where));

        foreach (self::advertisedServices($configuration) as $id) {
            self::assertTrue($container->has($id), sprintf('%s implies the service "%s"', $where, $id));
        }
    }

    #[TestDox('every document that teaches a configuration carries one')]
    public function testTeachingDocumentsCarryExamples(): void
    {
        $counted = array_fill_keys(self::TEACH_CONFIGURATION, 0);

        foreach (self::documentedConfigurations() as [$where]) {
            foreach (array_keys($counted) as $document) {
                if (str_starts_with($where, $document . ' ')) {
                    ++$counted[$document];
                }
            }
        }

        foreach ($counted as $document => $examples) {
            self::assertGreaterThan(0, $examples, sprintf('%s carries no medzuch_jwt examples; it used to', $document));
        }
    }

    #[TestDox('every medzuch_jwt service id the documentation mentions is a service some example builds')]
    public function testMentionedServiceIdsExist(): void
    {
        $available = [];

        foreach (self::documentedConfigurations() as [, $configuration]) {
            $available = [...$available, ...self::advertisedServices($configuration)];
        }

        $checked = 0;

        foreach (self::DOCUMENTS as $document) {
            preg_match_all('/\bmedzuch_jwt\.[a-z0-9_]+\.[a-z0-9_]+\b/', self::document($document), $matches);

            foreach (array_unique($matches[0]) as $id) {
                self::assertContains($id, $available, sprintf('%s tells the reader to use "%s"', $document, $id));

                ++$checked;
            }
        }

        // A regex that stopped matching — a renamed prefix, a fourth segment,
        // every id turned into a placeholder — would leave the loop above empty
        // and the case green, so the sweep asserts it swept.
        self::assertGreaterThan(10, $checked, 'the documentation should name service ids for the reader to use');
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

        foreach (self::documentedConfigurations() as [, $configuration]) {
            $registrations = $configuration['id_tokens'] ?? [];

            if (is_array($registrations)) {
                $declared = [...$declared, ...array_keys($registrations)];
            }
        }

        self::assertNotSame([], $declared, 'the documentation should configure at least one id_tokens registration');

        $injected = [];

        foreach (self::DOCUMENTS as $document) {
            preg_match_all('/IdTokenVerifier \$(\w+)/', self::document($document), $matches);

            $injected = [...$injected, ...$matches[1]];
        }

        self::assertNotSame([], $injected, 'the documentation should show the verifier being injected');

        foreach (array_unique($injected) as $argument) {
            self::assertContains($argument, $declared, sprintf('the documentation injects "IdTokenVerifier $%s", which no example registers', $argument));
        }
    }

    #[TestDox('every relative link in the documentation resolves, heading and all')]
    public function testInternalLinksResolve(): void
    {
        $checked = 0;

        foreach (self::DOCUMENTS as $document) {
            $directory = \dirname($document);

            preg_match_all('/\]\(([^)\s]+)\)/', self::document($document), $matches);

            foreach ($matches[1] as $link) {
                if (str_starts_with($link, 'http')) {
                    continue;
                }

                [$path, $fragment] = array_pad(explode('#', $link, 2), 2, null);

                $target = '' === $path ? $document : self::normalise(('.' === $directory ? '' : $directory . '/') . $path);

                self::assertFileExists(__DIR__ . '/../../' . $target, sprintf('%s links to "%s"', $document, $link));

                ++$checked;

                if (null === $fragment) {
                    continue;
                }

                self::assertContains(
                    $fragment,
                    self::headingAnchors($target),
                    sprintf('%s links to "%s", and %s has no such heading', $document, $link, $target),
                );
            }
        }

        // A link count that silently fell to nothing would pass every assertion
        // above, so the sweep asserts it swept.
        self::assertGreaterThan(10, $checked, 'the documentation should carry relative links');
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

        // A consumer promises the two RFC 6750 answers unconditionally.
        if (is_array($consumers)) {
            foreach (array_keys($consumers) as $consumer) {
                $ids[] = sprintf('medzuch_jwt.entry_point.%s', $consumer);
                $ids[] = sprintf('medzuch_jwt.access_denied.%s', $consumer);
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
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function documentedConfigurations(): iterable
    {
        foreach (self::DOCUMENTS as $document) {
            $text = self::document($document);

            preg_match_all('/```yaml\n(.*?)```/s', $text, $matches, \PREG_OFFSET_CAPTURE);

            foreach ($matches[1] as $match) {
                [$snippet, $offset] = $match;
                $where = sprintf('%s line %d', $document, substr_count(substr($text, 0, $offset), "\n") + 1);

                try {
                    $parsed = Yaml::parse($snippet);
                } catch (ParseException $e) {
                    throw new RuntimeException(sprintf('%s is not parsable YAML: %s', $where, $e->getMessage()), 0, $e);
                }

                if (!is_array($parsed) || !isset($parsed['medzuch_jwt']) || !is_array($parsed['medzuch_jwt'])) {
                    continue;
                }

                /** @var array<string, mixed> $configuration */
                $configuration = $parsed['medzuch_jwt'];

                yield $where => [$where, $configuration];
            }
        }
    }

    /**
     * GitHub's heading anchors: lowercased, backticks and punctuation dropped,
     * spaces hyphenated.
     *
     * @return list<string>
     */
    private static function headingAnchors(string $path): array
    {
        preg_match_all('/^#{1,6}\s+(.*)$/m', self::document($path), $matches);

        return array_map(
            static function (string $heading): string {
                $heading = strtolower(trim(str_replace('`', '', $heading)));

                return (string) preg_replace('/\s+/', '-', (string) preg_replace('/[^\w\s-]/u', '', $heading));
            },
            $matches[1],
        );
    }

    /**
     * Resolves the `..` segments a relative link uses to climb out of `docs/`.
     */
    private static function normalise(string $path): string
    {
        $segments = [];

        foreach (explode('/', $path) as $segment) {
            if ('..' === $segment) {
                array_pop($segments);

                continue;
            }

            if ('.' !== $segment && '' !== $segment) {
                $segments[] = $segment;
            }
        }

        return implode('/', $segments);
    }

    private static function document(string $path): string
    {
        $text = file_get_contents(__DIR__ . '/../../' . $path);

        if (false === $text) {
            throw new RuntimeException($path . ' is unreadable');
        }

        return $text;
    }
}
