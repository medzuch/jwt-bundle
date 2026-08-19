<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Makes the bundle's own services public for the duration of a test.
 *
 * Every service this bundle registers is private, as it should be: an
 * application reaches them through autowiring or by naming them in its own
 * configuration, never through `$container->get()`. Private services that
 * nothing references are removed during compilation, so without this pass a
 * test asking for `medzuch_jwt.clock` would fail with "service not found" —
 * describing the removal, not the wiring the test means to assert.
 *
 * Runs before removal so the definitions still exist.
 */
final class PublicForTestsPass implements CompilerPassInterface
{
    private const PREFIX = 'medzuch_jwt.';

    public function process(ContainerBuilder $container): void
    {
        foreach ($container->getDefinitions() as $id => $definition) {
            if (str_starts_with($id, self::PREFIX)) {
                $definition->setPublic(true);
            }
        }

        foreach ($container->getAliases() as $id => $alias) {
            if (str_starts_with($id, self::PREFIX)) {
                $alias->setPublic(true);
            }
        }
    }
}
