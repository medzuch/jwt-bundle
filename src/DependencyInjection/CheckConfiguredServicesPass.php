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
 * and does not mention `medzuch_jwt.logger`, which they did.
 *
 * It runs at {@see \Symfony\Component\DependencyInjection\Compiler\PassConfig::TYPE_BEFORE_REMOVING},
 * which is the latest point that is still ahead of Symfony's own check — that
 * one is a removing pass — and the earliest at which "does this service exist"
 * has a final answer. A service can be registered by *another pass* rather than
 * by an extension, and `monolog.logger.jwt` is exactly that: MonologBundle's
 * extension only records the channel, and its `LoggerChannelPass` creates the
 * service. At the default before-optimization priority this pass would refuse
 * the id its own configuration reference recommends, depending on the order
 * bundles happen to sit in `bundles.php`.
 *
 * **An id assembled from the environment is refused like any other.** Unlike a
 * `jwks_uri`, which is read at runtime and so cannot be judged here, a service
 * id has to exist while the container is built — an `%env()%` in one never
 * resolves to anything, whatever the environment says. Refusing it here names
 * the option that wrote it; letting it through means Symfony refusing it a
 * moment later about a service the application never wrote. Only `http_client`
 * gets this far in the first place: `clock`, `logger` and every optional name
 * are refused by the configuration tree, which reads a placeholder as the empty
 * string and says a service id cannot be blank.
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
