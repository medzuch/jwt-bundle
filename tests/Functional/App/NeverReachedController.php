<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use LogicException;

/**
 * Stands behind paths security is meant to settle on its own: the `json_login`
 * check path, which the firewall handles before routing, and a path an
 * `access_control` rule denies. Reaching this means security did neither.
 */
final class NeverReachedController
{
    public function __invoke(): never
    {
        throw new LogicException('Security should have handled this request before the controller.');
    }
}
