<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Refuses a configuration that names a service this application does not have.
 *
 * Symfony already refuses a missing service that something *references*. Two
 * cases are left over, and they are why this pass exists: an id nothing happens
 * to reference — `logger` with no consumer configured, `clock` where
 * `symfony/console` is absent — is removed silently rather than refused
 * (issue #3); and Symfony's message names the service rather than the option
 * that wrote it, sending the reader to an id they never typed.
 *
 * `TYPE_BEFORE_REMOVING` is load-bearing, not tidiness. It is the last point
 * ahead of Symfony's own check and the first at which "does this service exist"
 * has a final answer: `monolog.logger.jwt` is created by MonologBundle's
 * `LoggerChannelPass` rather than by its extension, so at the default priority
 * this pass would refuse the id its own configuration reference recommends,
 * depending on where bundles happen to sit in `bundles.php`.
 *
 * An `%env()%` inside a service id is refused like any other missing id: unlike
 * a `jwks_uri`, which is read at runtime, an id has to exist while the container
 * is built. Only `http_client` reaches here — the tree refuses the rest, reading
 * a placeholder as the empty string.
 *
 * Every problem is reported at once rather than the first: {@see ConfigurationGuard}
 * throws while registering and cannot see what comes after; this pass has the
 * whole list in front of it.
 *
 * @internal
 */
final class CheckConfiguredServicesPass implements CompilerPassInterface
{
    public function __construct(private readonly ConfiguredServices $configured) {}

    public function process(ContainerBuilder $container): void
    {
        $missing = [];

        foreach ($this->configured->all() as $path => $named) {
            if ($container->has($named['id'])) {
                continue;
            }

            $missing[] = sprintf(
                '  %s names "%s"%s',
                $path,
                $named['id'],
                null === $named['hint'] ? '' : ' — ' . $named['hint'],
            );
        }

        if ([] === $missing) {
            return;
        }

        throw new InvalidConfigurationException(sprintf(
            "medzuch_jwt names %s this application does not have:\n%s",
            1 === count($missing) ? 'a service' : 'services',
            implode("\n", $missing),
        ));
    }
}
