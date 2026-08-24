<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * A service that exists only after a compiler pass has run.
 *
 * Which is not an exotic arrangement: MonologBundle's extension records a
 * channel and its `LoggerChannelPass` turns it into `monolog.logger.<channel>`,
 * so the id this bundle's `logger` option gives as its own example is one no
 * amount of waiting for extensions will find.
 */
final class RegistersALateService implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        $container->register('test.late_denylist', InMemoryDenylist::class);
    }
}
