<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * The default: hand the identifier to the firewall's user provider and let the
 * application's own store answer who that is, roles included.
 *
 * @internal
 */
final class ProviderUserResolver implements UserResolverInterface
{
    public function __construct(private readonly string $identityClaim) {}

    public function badgeFor(ClaimsSet $claims): UserBadge
    {
        return new UserBadge(ClaimIdentity::from($claims, $this->identityClaim));
    }
}
