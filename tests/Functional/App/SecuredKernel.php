<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * A kernel with a real firewall in front of a real controller, so the round
 * trip a bundle promises — mint a token, present it, be someone — is asserted
 * through Symfony's own authenticator rather than by calling our handler.
 */
final class SecuredKernel extends Kernel
{
    use MicroKernelTrait;

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
        yield new SecurityBundle();
        yield new MedzuchJwtBundle();
    }

    public function getCacheDir(): string
    {
        return sprintf(
            '%s/medzuch-jwt-bundle-tests/secured-php%d-sf%d-%s',
            sys_get_temp_dir(),
            \PHP_VERSION_ID,
            Kernel::VERSION_ID,
            hash('xxh128', serialize($this->bundleConfig)),
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
        ]);

        $container->extension('security', [
            'providers' => [
                'users' => ['memory' => ['users' => ['alice' => ['roles' => ['ROLE_USER']]]]],
            ],
            'firewalls' => [
                'api' => [
                    'pattern' => '^/api',
                    'stateless' => true,
                    'provider' => 'users',
                    'access_token' => ['token_handler' => 'medzuch_jwt.handler.api'],
                ],
            ],
            'access_control' => [
                ['path' => '^/api', 'roles' => 'IS_AUTHENTICATED_FULLY'],
            ],
        ]);

        $container->extension('medzuch_jwt', $this->bundleConfig);

        $container->services()
            ->set(WhoAmIController::class)
            ->autowire()
            ->public()

            // Without Monolog, Symfony's fallback logger writes every firewall
            // decision to stderr, which PHPUnit reports as unexpected output.
            // The bundle's own logging is asserted where it belongs — through
            // the `logger` configuration key, not through the kernel's default.
            ->set('logger', NullLogger::class);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('whoami', '/api/whoami')->controller(WhoAmIController::class);
    }
}
