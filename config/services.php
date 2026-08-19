<?php

declare(strict_types=1);

use Medzuch\Jwt\Primitives\SystemClock;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * Bundle-internal service definitions.
 *
 * PHP rather than YAML on purpose: these are ours, they reference real class
 * names, and a typo should be a static-analysis finding rather than a runtime
 * "service not found". The *application-facing* configuration stays YAML,
 * matching how every other bundle is configured.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        // The library's PSR-20 clock, UTC wall time. Overridden by an alias
        // when `medzuch_jwt.clock` names a service (see MedzuchJwtBundle).
        ->set('medzuch_jwt.clock', SystemClock::class);
};
