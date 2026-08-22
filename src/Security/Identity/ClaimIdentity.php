<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Identity;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;

/**
 * The identifier a token names, for the modes that take it from a claim.
 *
 * A token that names nobody is refused as a claim failure, not an identity
 * one: `identity_refused` means the application looked at who the token named
 * and said no, and there is nobody to look at here. It is also the same verdict
 * the library reaches when the claim is present but not a string, and one
 * defect landing in two buckets depending on how it went wrong would be a
 * metric nobody can read.
 *
 * @internal
 */
final class ClaimIdentity
{
    public static function from(ClaimsSet $claims, string $claim): string
    {
        $identity = $claims->getString($claim);

        if (null === $identity || '' === $identity) {
            throw new RejectedTokenException(
                RejectionReason::ClaimsRefused,
                sprintf('Access token carries no "%s" claim to identify the user.', $claim),
            );
        }

        return $identity;
    }
}
