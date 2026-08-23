<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DataCollector;

use Medzuch\JwtBundle\Security\TraceableAccessTokenHandler;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Puts a tracing decorator in front of the handler a firewall actually calls,
 * and only where somebody is watching.
 *
 * A pass rather than `loadExtension()`, because the question it asks —
 * "is the profiler enabled?" — is answered by another bundle's extension, and
 * extensions run in an order no bundle should depend on. Passes run after all
 * of them.
 *
 * It is the bundle's only compiler pass, and it lives beside the collector
 * because the panel is the only thing it exists for — `DependencyInjection/`
 * would be a directory holding one file whose subject is here.
 *
 * It must run before child definitions are resolved, which is what the default
 * `TYPE_BEFORE_OPTIMIZATION` gives it: by `TYPE_OPTIMIZE` every
 * {@see ChildDefinition} has been flattened into a plain one, the loop below
 * would match nothing, and the panel would be empty against a container that
 * built cleanly.
 *
 * @internal
 */
final class CollectVerdictsPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->has('profiler') || !$container->hasDefinition('medzuch_jwt.data_collector')) {
            // Removed here and nowhere else: FrameworkBundle's own ProfilerPass
            // returns before it looks at a single `data_collector` when there is
            // no profiler, and an unused private service is dropped only while
            // it stays private. Which leaves the decorator, and a wrapper
            // recording into nothing has no business on the hot path of every
            // authenticated request.
            $container->removeDefinition('medzuch_jwt.data_collector');

            return;
        }

        $consumers = [];

        foreach ($container->findTaggedServiceIds('medzuch_jwt.token_handler') as $id => $tags) {
            $consumers[$id] = (string) ($tags[0]['consumer'] ?? $id);
        }

        foreach ($container->getDefinitions() as $id => $definition) {
            // What the firewall calls is not this bundle's handler service but a
            // child of it: `access_token: { token_handler: … }` becomes
            // `new ChildDefinition($id)` under a name keyed by the firewall
            // (SecurityBundle's ServiceTokenHandlerFactory). Decorating the
            // parent leaves that child untouched — the panel would have stayed
            // empty on every request — and could not be done safely anyway,
            // since the child would then inherit from the decorator.
            if (!$definition instanceof ChildDefinition || !isset($consumers[$definition->getParent()])) {
                continue;
            }

            $container->setDefinition($id . '.traceable', (new Definition(TraceableAccessTokenHandler::class))
                ->setArguments([
                    new Reference($id . '.traceable.inner'),
                    $consumers[$definition->getParent()],
                    new Reference('medzuch_jwt.data_collector'),
                ])
                ->setDecoratedService($id));
        }
    }
}
