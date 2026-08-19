<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
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
 * @see https://github.com/medzuch/jwt-bundle/blob/main/docs/plan.md the design, the feature catalogue and the roadmap
 */
final class MedzuchJwtBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $root = $definition->rootNode();
        \assert($root instanceof ArrayNodeDefinition);

        $root
            ->children()
                ->scalarNode('clock')
                    ->defaultNull()
                    ->info('Service id of a PSR-20 clock. Null uses the library\'s SystemClock.')
                    ->example('app.frozen_clock')
                    ->validate()
                        ->ifTrue(static fn(mixed $value): bool => null !== $value && (!\is_string($value) || '' === trim($value)))
                        ->thenInvalid('medzuch_jwt.clock must be a non-empty service id, got %s')
                    ->end()
                ->end();
    }

    /**
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        $clock = $config['clock'] ?? null;

        if (is_string($clock)) {
            // setAlias() drops the definition from services.php, so the
            // container holds exactly one medzuch_jwt.clock either way.
            $builder->setAlias('medzuch_jwt.clock', $clock);
        }
    }
}
