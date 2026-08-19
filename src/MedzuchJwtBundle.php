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
 * Phase 0 registers the clock and nothing else. The named collections the
 * design calls for (`keys`, `issuers`, `consumers`) arrive in Phase 1 — as maps
 * from their first release, because retrofitting names onto a scalar tree later
 * would break every application already configured.
 *
 * @see https://github.com/medzuch/jwt-bundle/blob/main/docs/plan.md
 */
final class MedzuchJwtBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $root = $definition->rootNode();

        // `rootNode()` is declared as returning the `NodeDefinition` base type,
        // which has no `children()`. Every configuration root is in fact an
        // array node; asserting it keeps static analysis honest instead of
        // silencing the call site.
        \assert($root instanceof ArrayNodeDefinition);

        // The chain stops at the node's own `end()`: every `end()` is typed
        // `?NodeParentInterface`, so calling anything on its result is a
        // level-9 finding. Nothing needs the root back — `children()` attaches
        // each node as it is built.
        $root
            ->children()
                ->scalarNode('clock')
                    ->defaultNull()
                    ->info('Service id of a PSR-20 clock. Null uses the library\'s SystemClock.')
                    ->example('app.frozen_clock')
                    // A scalar node accepts `123`, `false` and `''` as happily
                    // as a service id, and each of those would have fallen
                    // through to the default — an application that mistyped
                    // its clock id would have silently run on wall time. The
                    // key is optional; what it must not be is present and
                    // meaningless.
                    ->validate()
                        ->ifTrue(static fn (mixed $value): bool => null !== $value && (!\is_string($value) || '' === trim($value)))
                        ->thenInvalid('medzuch_jwt.clock must be a non-empty service id, got %s')
                    ->end()
                ->end();
    }

    /**
     * `array<array-key, mixed>` rather than `array<string, mixed>`: narrowing
     * the key type of an inherited parameter breaks contravariance, and level 9
     * insists on *some* value type. This spelling satisfies both — it is what
     * the bare `array` in the parent signature already means.
     *
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.php');

        // A configured clock replaces the default rather than decorating it:
        // `setAlias()` drops the definition registered in services.php, so
        // there is exactly one `medzuch_jwt.clock` in the container either way.
        // Everything time-dependent in this bundle resolves that id, so an
        // application can freeze time in tests by pointing it at a FrozenClock
        // without any test-only branch in the bundle itself.
        // The configuration tree has already refused anything that is neither
        // null nor a non-empty service id; `is_string()` is what tells static
        // analysis so, since `$config` is untyped at this boundary.
        $clock = $config['clock'] ?? null;

        if (is_string($clock)) {
            $builder->setAlias('medzuch_jwt.clock', $clock);
        }
    }
}
