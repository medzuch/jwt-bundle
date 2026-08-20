<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * What a verified token turns into.
 *
 * One implementation per `user.mode`, so the handler holds a collaborator
 * rather than a pair of nullable options encoding three behaviours. Naming the
 * user is part of the job rather than something decided before: two modes read
 * a configured claim, and the third asks the application, which may build an
 * identity out of claims no single one of which is it.
 *
 * @internal
 */
interface UserResolverInterface
{
    public function badgeFor(ClaimsSet $claims): UserBadge;
}
