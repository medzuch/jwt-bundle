<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\Jwt\Primitives\SystemClock;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;

/**
 * A kernel that makes nothing of the bundle's public.
 *
 * {@see TestKernel} and its siblings run `PublicForTestsPass` so a test can
 * reach the services it is about. That is right for them and wrong here:
 * a public alias has to resolve, so under that kernel a `clock` naming a
 * service nobody has already failed — and a test asserting the refusal would
 * have been asserting the test kernel's own wiring rather than the bundle's.
 *
 * What this kernel has instead is the handful of services an application would
 * bring, under `test.` names, so a configuration naming a service that *does*
 * exist has something to name.
 */
final class BareKernel extends Kernel
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

            $container->register('test.clock', SystemClock::class);
            $container->register('test.cache', ArrayCache::class);
            $container->register('test.http_client', StubHttpClient::class);

            $container->loadFromExtension('medzuch_jwt', $this->bundleConfig);
        });
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/medzuch-jwt-bundle-bare/' . hash('xxh128', serialize($this->bundleConfig));
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }
}
