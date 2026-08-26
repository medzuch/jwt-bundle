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
use Symfony\Component\ExpressionLanguage\ExpressionFunction;
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
    private const DOCUMENTS = ['README.md', 'docs/cookbook.md', 'UPGRADE.md', 'BACKWARD-COMPATIBILITY.md', 'docs/plan.md'];

    /**
     * Service ids that are one segment rather than two, listed because the
     * sweep below cannot match them by shape. Loosening its regex to make the
     * second segment optional looks cheaper and is wrong: `medzuch_jwt.key`,
     * `medzuch_jwt.consumer` and `medzuch_jwt.denylist` are prefixes the
     * documentation writes when it means "one per name", `medzuch_jwt.jwks` is
     * a configuration section, and `medzuch_jwt.yaml` is a filename — twenty-two
     * such matches across these five documents, none of them a service to
     * resolve. So the exceptions are named.
     */
    private const SINGLE_SEGMENT_IDS = [
        'medzuch_jwt.clock',
        'medzuch_jwt.jwks_controller',
        'medzuch_jwt.scope_voter',
        'medzuch_jwt.scope_expression_provider',
    ];

    /**
     * Documents whose job is to show a configuration that works, so each has to
     * carry at least one. `UPGRADE.md` is not one of them: its YAML is
     * deliberately `diff` rather than `yaml`, because the half being migrated
     * away from is configuration that no longer compiles — which is the point
     * of showing it.
     *
     * `docs/plan.md` was the last to join, and it is the reason the list is
     * worth keeping honest: it was the one document with YAML nothing compiled,
     * and by 1.0 its §4 tree had drifted into a configuration the bundle would
     * refuse — options renamed, sections that never shipped, a duplicated key.
     */
    private const TEACH_CONFIGURATION = ['README.md', 'docs/cookbook.md', 'docs/plan.md'];

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
            $text = self::document($document);

            preg_match_all('/\bmedzuch_jwt\.[a-z0-9_]+\.[a-z0-9_]+\b/', $text, $matches);

            $mentioned = $matches[0];

            foreach (self::SINGLE_SEGMENT_IDS as $id) {
                // Not `\b`: that would also match the id as the prefix of a
                // longer one, and the point of the list is the ids that end
                // where they end.
                if (1 === preg_match('/\b' . preg_quote($id, '/') . '(?![a-z0-9_.])/', $text)) {
                    $mentioned[] = $id;
                }
            }

            foreach (array_unique($mentioned) as $id) {
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

    #[TestDox('every document the distributed ones link to is distributed too')]
    public function testLinkedDocumentsShipWithThePackage(): void
    {
        // `.gitattributes` decides what a `composer require` unpacks into
        // `vendor/`, and the documents above are all in it. A link from one of
        // them into a file the archive left out is a broken link in every
        // installation — invisible here, where the whole repository is present,
        // which is why this asks git rather than the filesystem.
        $targets = [];

        foreach (self::DOCUMENTS as $document) {
            $directory = \dirname($document);

            preg_match_all('/\]\(([^)\s]+)\)/', self::document($document), $matches);

            foreach ($matches[1] as $link) {
                if (str_starts_with($link, 'http') || str_starts_with($link, '#')) {
                    continue;
                }

                [$path] = explode('#', $link, 2);

                if ('' === $path) {
                    continue;
                }

                $target = self::normalise(('.' === $directory ? '' : $directory . '/') . $path);
                $targets[$target] = $document;
            }
        }

        self::assertNotSame([], $targets, 'the distributed documents should link to something');

        foreach (self::excludedFromTheArchive(array_keys($targets)) as $excluded) {
            self::fail(sprintf(
                '%s links to "%s", which .gitattributes keeps out of the distributed archive',
                $targets[$excluded],
                $excluded,
            ));
        }
    }

    /**
     * Which of these paths `git archive` would leave out, a directory rule
     * counting for everything under it.
     *
     * @param list<string> $paths
     *
     * @return list<string>
     */
    private static function excludedFromTheArchive(array $paths): array
    {
        $asked = [];

        foreach ($paths as $path) {
            for ($candidate = $path; '.' !== $candidate; $candidate = \dirname($candidate)) {
                $asked[$candidate] = $path;
            }
        }

        $command = 'git -C ' . escapeshellarg(\dirname(__DIR__, 2)) . ' check-attr export-ignore -- '
            . implode(' ', array_map('escapeshellarg', array_keys($asked))) . ' 2>/dev/null';

        $output = [];
        $status = 0;
        exec($command, $output, $status);

        self::assertSame(0, $status, 'git check-attr could not answer; this test needs a git checkout');
        self::assertCount(count($asked), $output, 'git check-attr answered for a different set of paths');

        $excluded = [];

        foreach ($output as $line) {
            // "<path>: export-ignore: set" — the path may itself contain ": ",
            // so the two known fields are taken off the end.
            $fields = explode(': ', $line);
            $verdict = array_pop($fields);
            array_pop($fields);
            $candidate = implode(': ', $fields);

            if ('set' === $verdict && isset($asked[$candidate])) {
                $excluded[$asked[$candidate]] = true;
            }
        }

        return array_keys($excluded);
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

        // A published set is registered on a condition rather than on a name,
        // so it is the one promised id an example advertises by what it says
        // rather than by what it calls something.
        $jwks = $configuration['jwks'] ?? [];
        $published = is_array($jwks) ? $jwks['keys'] ?? [] : [];

        if (is_array($published) && [] !== $published) {
            $ids[] = 'medzuch_jwt.jwks.key_set';
            $ids[] = 'medzuch_jwt.jwks_controller';
        }

        // Registered by every example, because they are registered by every
        // container: the clock is the extension's own default and the voter
        // answers only `SCOPE_*`, so neither has a condition to meet. The
        // expression provider does — `symfony/expression-language` is optional,
        // and `suggest`ed rather than required.
        $ids[] = 'medzuch_jwt.clock';
        $ids[] = 'medzuch_jwt.scope_voter';

        if (class_exists(ExpressionFunction::class)) {
            $ids[] = 'medzuch_jwt.scope_expression_provider';
        }

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
