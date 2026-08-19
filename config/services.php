<?php

declare(strict_types=1);

use Medzuch\Jwt\Primitives\SystemClock;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set('medzuch_jwt.clock', SystemClock::class);
};
