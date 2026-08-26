<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle;

use Medzuch\JwtBundle\DataCollector\CollectVerdictsPass;
use Medzuch\JwtBundle\DependencyInjection\CheckConfiguredServicesPass;
use Medzuch\JwtBundle\DependencyInjection\ConfigurationTree;
use Medzuch\JwtBundle\DependencyInjection\ConfiguredServices;
use Medzuch\JwtBundle\DependencyInjection\ServiceRegistrar;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * Wires `medzuch/jwt-php` into a Symfony application.
 *
 * `AbstractBundle` derives the configuration root from this class name, so the
 * root key is `medzuch_jwt` and the namespace prefix is `Medzuch\JwtBundle\`.
 * Both are public API: renaming either is a breaking change.
 *
 * What is left here is what Symfony calls. The work is next door, `@internal`:
 * {@see ConfigurationTree} declares the tree, {@see ServiceRegistrar} turns it
 * into definitions, {@see DependencyInjection\ConsoleCommands} registers the
 * five commands where `symfony/console` is installed,
 * {@see DependencyInjection\ConfigurationGuard} holds the refusals that need
 * more than one node to decide, and {@see DependencyInjection\KeyEntries}
 * normalises the `keys:` section they all read.
 *
 * @see https://github.com/medzuch/jwt-bundle/blob/main/docs/plan.md the design, the feature catalogue and the roadmap
 */
final class MedzuchJwtBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        ConfigurationTree::define($definition);
    }

    /**
     * Filled by {@see ServiceRegistrar} while the extension runs and read by
     * the pass {@see self::build()} registers, which run at opposite ends of
     * one container build on this one object.
     */
    private readonly ConfiguredServices $configured;

    public function __construct()
    {
        $this->configured = new ConfiguredServices();
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        // After every extension, because whether there is a profiler to collect
        // for is another bundle's answer.
        $container->addCompilerPass(new CollectVerdictsPass());

        // Same reason, other subject, and later still: whether a service the
        // configuration names exists can be answered by another bundle's
        // *pass* rather than its extension — MonologBundle's `LoggerChannelPass`
        // is what creates `monolog.logger.jwt`, which this bundle's own
        // configuration reference recommends. TYPE_BEFORE_REMOVING is the last
        // point ahead of Symfony's own missing-service check, which is a
        // removing pass.
        $container->addCompilerPass(
            new CheckConfiguredServicesPass($this->configured),
            PassConfig::TYPE_BEFORE_REMOVING,
        );
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        (new ServiceRegistrar($this->configured))->register($config, $container, $builder);
    }
}
