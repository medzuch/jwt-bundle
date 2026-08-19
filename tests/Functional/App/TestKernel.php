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
     * @param array<string, mixed> $bundleConfig configuration under the `medzuch_jwt` root key
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
            $framework = ['secret' => 'test-secret', 'test' => true];

            // Version-conditional, and deliberately only here: 6.4 deprecates
            // leaving `http_method_override` unset, while later majors dropped
            // the option altogether, so neither a fixed value nor omission
            // works across the supported window. DEC-2 rules this out in
            // `src/` — this is the test harness, whose job is to absorb such
            // differences so the bundle itself never has to.
            if (Kernel::VERSION_ID < 70000) {
                $framework['http_method_override'] = false;
            }

            $container->loadFromExtension('framework', $framework);
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
