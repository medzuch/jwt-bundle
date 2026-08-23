<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Bundle\WebProfilerBundle\WebProfilerBundle;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * A kernel with a profiler behind the firewall, which is the only place the
 * panel exists at all: the collector is removed where no profiler collects.
 */
final class ProfiledKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param array<array-key, mixed> $bundleConfig
     */
    public function __construct(private readonly array $bundleConfig = [])
    {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new TwigBundle();
        yield new WebProfilerBundle();
        yield new MedzuchJwtBundle();
    }

    public function getCacheDir(): string
    {
        return sprintf(
            '%s/medzuch-jwt-bundle-tests/profiled-php%d-sf%d-%s',
            sys_get_temp_dir(),
            \PHP_VERSION_ID,
            Kernel::VERSION_ID,
            hash('xxh128', serialize($this->bundleConfig)),
        );
    }

    public function getProjectDir(): string
    {
        return $this->getCacheDir();
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new PublicForTestsPass(), PassConfig::TYPE_BEFORE_REMOVING);
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test-secret',
            'test' => true,
            'router' => ['utf8' => true],
            // The whole point of this kernel: without a profiler the pass
            // removes the collector and the decorators are never registered.
            'profiler' => ['enabled' => true, 'collect' => true],
        ]);

        $container->extension('twig', ['default_path' => $this->getProjectDir() . '/templates']);
        $container->extension('web_profiler', ['toolbar' => false, 'intercept_redirects' => false]);

        $container->extension('security', [
            'providers' => ['users' => ['memory' => ['users' => ['alice' => ['password' => 'x', 'roles' => ['ROLE_USER']]]]]],
            'firewalls' => ['api' => [
                'pattern' => '^/api',
                'stateless' => true,
                'provider' => 'users',
                'access_token' => ['token_handler' => 'medzuch_jwt.handler.api'],
            ]],
            'access_control' => [['path' => '^/api', 'roles' => 'IS_AUTHENTICATED_FULLY']],
        ]);

        $container->extension('medzuch_jwt', $this->bundleConfig);

        $container->services()
            ->set(WhoAmIController::class)->autowire()->public()
            ->set('logger', CollectingLogger::class)->public();
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('whoami', '/api/whoami')->controller(WhoAmIController::class);
    }
}
