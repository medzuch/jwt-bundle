<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * The identifier a token names, for the modes that take it from a claim.
 *
 * @internal
 */
final class ClaimIdentity
{
    public static function from(ClaimsSet $claims, string $claim): string
    {
        $identity = $claims->getString($claim);

        if (null === $identity || '' === $identity) {
            throw new BadCredentialsException(sprintf('Access token carries no "%s" claim to identify the user.', $claim));
        }

        return $identity;
    }
}
