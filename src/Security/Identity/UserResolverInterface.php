<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * What a verified token turns into, once it is known who it names.
 *
 * One implementation per `user.mode`, so the handler holds a collaborator
 * rather than a pair of nullable options encoding three behaviours.
 *
 * @internal
 */
interface UserResolverInterface
{
    public function badgeFor(string $identifier, ClaimsSet $claims): UserBadge;
}
