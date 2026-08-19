<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\HttpKernel\Kernel;

/**
 * Smallest kernel that can boot the bundle for real.
 *
 * The point of a functional test here is that the container is *compiled* —
 * a configuration tree that parses and services that wire are two different
 * claims, and only the second one is what an application depends on.
 */
final class TestKernel extends Kernel
{
    /**
     * @param array<array-key, mixed> $bundleConfig configuration under the `medzuch_jwt` root key
     */
    public function __construct(private readonly array $bundleConfig = [])
    {
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
            // Symfony 6.4 deprecates leaving `http_method_override` unset,
            // while later majors dropped the option, so no single value works
            // across the window. Rather than branch on Kernel::VERSION_ID — a
            // constant every analyser folds, making the comparison "always
            // true" on one leg and "always false" on the next — the harness
            // simply wears the 6.4 deprecation notice. Nothing fails on it
            // (see phpunit.xml.dist), and the bundle itself stays free of
            // version-conditional code, which is what DEC-2 actually asks for.
            $container->loadFromExtension('framework', ['secret' => 'test-secret', 'test' => true]);
            $container->loadFromExtension('medzuch_jwt', $this->bundleConfig);

            // Stand-in for an application-provided clock, so the override path
            // is exercised against a real service rather than a mock id.
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

    public function getCacheDir(): string
    {
        // Keyed by the configuration, not just the environment: two tests that
        // boot different configurations must not share a compiled container,
        // or the second one silently asserts against the first one's wiring.
        return sys_get_temp_dir() . '/medzuch-jwt-bundle-tests/' . $this->configurationKey();
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }

    private function configurationKey(): string
    {
        return hash('xxh128', serialize($this->bundleConfig));
    }
}
