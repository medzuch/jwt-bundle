<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Makes the bundle's own services public for the duration of a test.
 *
 * They are private in an application, as they should be, and private services
 * nothing references are removed during compilation — so a test asking for one
 * would fail with "service not found" rather than with whatever it meant to
 * assert. Registered before the removal pass.
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
