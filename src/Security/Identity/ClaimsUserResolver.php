<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\JwtBundle\Security\User\ClaimRoles;
use Medzuch\JwtBundle\Security\User\JwtUser;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * The token is the record: no store is consulted, and the user is what the
 * claims say.
 *
 * The loader is a closure rather than an eagerly built user because
 * {@see UserBadge} calls it only when the badge is actually resolved, and a
 * request refused earlier — by an access rule, say — should not have built one.
 *
 * @internal
 */
final class ClaimsUserResolver implements UserResolverInterface
{
    public function __construct(
        private readonly string $identityClaim,
        private readonly ClaimRoles $roles,
    ) {}

    public function badgeFor(ClaimsSet $claims): UserBadge
    {
        return new UserBadge(
            ClaimIdentity::from($claims, $this->identityClaim),
            fn(string $identifier): JwtUser => new JwtUser($identifier, $this->roles->from($claims), $claims),
        );
    }
}
