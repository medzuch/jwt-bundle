<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Keeps the service ids carrying a tag, so a test can assert one.
 *
 * Tags exist only while the container is being built; after compilation they
 * are gone, and `has()` proves a service exists without proving it is reachable
 * from whatever collects the tag. Recording them into a parameter is what makes
 * that assertable.
 */
final class RecordsTaggedServicesPass implements CompilerPassInterface
{
    public const PARAMETER = 'test.tagged';

    /** @var list<string> */
    private const TAGS = ['security.voter', 'security.expression_language_provider'];

    public function process(ContainerBuilder $container): void
    {
        $tagged = [];

        foreach (self::TAGS as $tag) {
            $tagged[$tag] = array_keys($container->findTaggedServiceIds($tag));
        }

        $container->setParameter(self::PARAMETER, $tagged);
    }
}
