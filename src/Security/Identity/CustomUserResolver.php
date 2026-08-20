<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\JwtBundle\Security\User\JwtUserFactoryInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Neither the store nor the claims alone: the application maps a verified token
 * to its own notion of a user.
 *
 * @internal
 */
final class CustomUserResolver implements UserResolverInterface
{
    public function __construct(private readonly JwtUserFactoryInterface $factory) {}

    public function badgeFor(string $identifier, ClaimsSet $claims): UserBadge
    {
        return new UserBadge(
            $identifier,
            fn(string $identifier): UserInterface => $this->factory->userFrom($claims),
        );
    }
}
