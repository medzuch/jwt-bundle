<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\JwtBundle\Security\User\JwtUserFactoryInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Neither the store nor a configured claim: the application maps a verified
 * token to its own notion of a user, and names it too — `user.identity_claim`
 * is not consulted in this mode.
 *
 * @internal
 */
final class CustomUserResolver implements UserResolverInterface
{
    public function __construct(private readonly JwtUserFactoryInterface $factory) {}

    public function badgeFor(ClaimsSet $claims): UserBadge
    {
        // Built now rather than through the badge's loader, because the user
        // is also what names it: a factory may derive an identity from claims
        // no single one of which is the identifier, and a badge whose name
        // disagreed with the user it loads would put two identities in the
        // logs for one request.
        $user = $this->factory->userFrom($claims);

        return new UserBadge($user->getUserIdentifier(), static fn(): UserInterface => $user);
    }
}
