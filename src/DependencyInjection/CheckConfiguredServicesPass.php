<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Refuses a configuration that names a service this application does not have.
 *
 * Symfony catches most of these already: a missing service that something
 * *references* fails in `CheckExceptionOnInvalidReferenceBehaviorPass`. Two
 * things are left over, and both are why this exists.
 *
 * **An id nothing happens to reference is not checked at all.** `logger` with
 * no consumer, issuer, ID token or remote set configured is referenced by
 * nothing, so a typo in it compiles clean and the container is simply built
 * without the logging that was asked for. `clock` is the same wherever
 * `symfony/console` is absent — with the commands unregistered and no profile
 * to build, the alias is unreferenced, removed, and silent. That is the shape
 * issue #3 described.
 *
 * **The message names a service, never the configuration.** Symfony says
 * `medzuch_jwt.consumer.api has a dependency on a non-existent service
 * "app.no_such_logger"`, which sends the reader to a service they did not write
 * and does not mention `medzuch_jwt.logger`, which they did. Running before
 * Symfony's own check means ours is the message they get.
 *
 * Every problem is reported at once rather than the first: unlike the checks in
 * {@see \Medzuch\JwtBundle\MedzuchJwtBundle}, which throw while registering and
 * so cannot see what comes after, this pass has the whole list in front of it,
 * and a deploy fixing one typo per build is a deploy nobody enjoys.
 *
 * @internal
 */
final class CheckConfiguredServicesPass implements CompilerPassInterface
{
    /**
     * Where {@see \Medzuch\JwtBundle\MedzuchJwtBundle::loadExtension()} leaves
     * what it read, keyed by the configuration path that named it.
     *
     * A parameter rather than a constructor argument: `build()` runs before any
     * extension does, so the pass exists before there is anything to give it.
     * It is removed here, so nothing of it reaches the compiled container.
     */
    public const CONFIGURED = 'medzuch_jwt.configured_services';

    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter(self::CONFIGURED)) {
            return;
        }

        /** @var array<string, array{id: string, hint: string|null}> $configured */
        $configured = $container->getParameter(self::CONFIGURED);

        $container->getParameterBag()->remove(self::CONFIGURED);

        $missing = [];

        foreach ($configured as $path => $named) {
            // A service id read from the environment cannot be checked while
            // the container is being built, because the environment is not read
            // until it is used. It is also a strange thing to write: the wiring
            // of an application is not a deployment variable.
            if (str_contains($named['id'], '%env(')) {
                continue;
            }

            $id = $container->getParameterBag()->resolveValue($named['id']);

            if (!is_string($id) || $container->has($id)) {
                continue;
            }

            $missing[] = sprintf(
                '  %s names "%s"%s',
                $path,
                $id,
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
