<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
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
            $container->loadFromExtension('framework', ['secret' => 'test-secret', 'test' => true]);
            $container->loadFromExtension('medzuch_jwt', $this->bundleConfig);

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
            hash('xxh128', serialize($this->bundleConfig)),
        );
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }
}
