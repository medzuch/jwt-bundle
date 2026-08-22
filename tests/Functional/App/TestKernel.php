<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Event\JwtRejectedEvent;
use Medzuch\JwtBundle\Event\JwtVerifiedEvent;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;

/**
 * Smallest kernel that can boot the bundle for real, so the tests assert
 * against a compiled container rather than a parsed configuration tree.
 *
 * `framework.http_method_override` is deliberately left unset: 6.4 deprecates
 * the omission and later majors dropped the option, so no single value works
 * across the supported window. The resulting 6.4 deprecation notice fails
 * nothing (see `phpunit.xml.dist`) and keeps the bundle free of
 * version-conditional code.
 */
final class TestKernel extends Kernel
{
    /**
     * @param array<array-key, mixed> $bundleConfig configuration under the `medzuch_jwt` root key
     * @param array<string, string>   $aliases      service ids an application would provide, for a test
     *                                              whose subject names one — kept out of the default
     *                                              container so the other tests' wiring stays honest
     */
    public function __construct(
        private readonly array $bundleConfig = [],
        private readonly array $aliases = [],
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new MedzuchJwtBundle();
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', ['secret' => 'test-secret', 'test' => true]);
            $container->loadFromExtension('medzuch_jwt', $this->bundleConfig);

            $container->register('test.logger', CollectingLogger::class)->setPublic(true);

            // Without Monolog, Symfony's fallback logger writes every dispatched
            // event to stderr, which PHPUnit reports as unexpected output.
            // Collecting rather than discarding, for the same reason
            // SecuredKernel does it: a silenced kernel also silences the
            // deprecations a boot would report.
            $container->register('logger', CollectingLogger::class)->setPublic(true);

            // An identity provider and a cache the tests can interrogate. They
            // cost nothing to the tests that ignore them, and a remote JWK Set
            // cannot be exercised without both.
            $container->register('test.http_client', StubHttpClient::class)->setPublic(true);
            $container->register('test.cache', ArrayCache::class)->setPublic(true);
            $container->register('test.cache_pool', ArrayAdapter::class)->setPublic(true);
            $container->register('test.user_factory', TenantUserFactory::class)->setPublic(true);
            $container->register('test.denylist', InMemoryDenylist::class)->setPublic(true);

            // Listening always, because it records and decides nothing: a
            // consumer announcing a verdict is part of every test's wiring,
            // and a listener registered only where it is asserted would leave
            // the dispatch itself unexercised everywhere else.
            $container->register('test.verification_listener', RecordsVerification::class)
                ->setPublic(true)
                ->addTag('kernel.event_listener', ['event' => JwtVerifiedEvent::class, 'method' => 'onVerified'])
                ->addTag('kernel.event_listener', ['event' => JwtRejectedEvent::class, 'method' => 'onRejected']);

            // Registered only where it can be satisfied: it asks for an ID
            // token verifier by argument name, which is the whole of what it
            // is here to prove.
            $registrations = $this->bundleConfig['id_tokens'] ?? null;

            if (is_array($registrations) && isset($registrations['partner'])) {
                $container->register('test.oidc_callback', OidcCallback::class)
                    ->setAutowired(true)
                    ->setPublic(true);
            }

            foreach ($this->aliases as $id => $target) {
                $container->setAlias($id, $target);
            }

            $container->register('test.frozen_clock', FrozenClock::class)
                ->setFactory([FrozenClock::class, 'at'])
                ->addArgument('2026-01-01T00:00:00+00:00')
                ->setPublic(true);
        });
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new PublicForTestsPass(), PassConfig::TYPE_BEFORE_REMOVING);
    }

    /**
     * Keyed by configuration *and* runtime, so two boots never share a
     * container compiled for a different dependency set.
     */
    public function getCacheDir(): string
    {
        return sprintf(
            '%s/medzuch-jwt-bundle-tests/php%d-sf%d-%s',
            sys_get_temp_dir(),
            \PHP_VERSION_ID,
            Kernel::VERSION_ID,
            hash('xxh128', serialize([$this->bundleConfig, $this->aliases])),
        );
    }

    /**
     * Points away from the repository: with the project dir defaulting to the
     * package root, booting a kernel writes generated artefacts (a 68 KB
     * `config/reference.php`, among others) straight into the bundle's own
     * `config/` — a source directory here, not an application's.
     */
    public function getProjectDir(): string
    {
        return $this->getCacheDir();
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }
}
