<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use LogicException;

/**
 * Stands behind the `json_login` check path, which the firewall handles before
 * routing. Reaching this means the firewall did not.
 */
final class NeverReachedController
{
    public function __invoke(): never
    {
        throw new LogicException('The json_login listener should have handled this request.');
    }
}
