<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\User;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Turns a verified token into whatever a particular application calls a user.
 *
 * Implement this and name the service under `user.factory` when neither of the
 * other two modes fits: `provider` when a user store is the authority, and
 * `claims` when the token is.
 *
 * The token has already been verified when this is called — signature, issuer,
 * audience, expiry and the consumer's own rules. What is left is a mapping
 * decision, so refusing here means "this is a valid token for nobody I know",
 * which is an {@see AuthenticationException}, not a server error.
 */
interface JwtUserFactoryInterface
{
    /**
     * @throws AuthenticationException when the claims describe no user this application accepts
     */
    public function userFrom(ClaimsSet $claims): UserInterface;
}
