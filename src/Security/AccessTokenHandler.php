<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Profile\ProfileConsumer;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Turns a validated token into a `UserBadge` for Symfony's native
 * `access_token` authenticator. One instance per configured consumer.
 *
 * Every library failure becomes the same `BadCredentialsException`, carrying the
 * original as `previous`: the reason belongs in the log, not in the response.
 * Which claim identifies the user is configuration, because `sub` is only the
 * default answer — a token from a third-party issuer may carry the local
 * identity somewhere else entirely.
 */
final class AccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private readonly ProfileConsumer $consumer,
        private readonly string $identityClaim,
    ) {}

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        try {
            $claims = $this->consumer->parse($accessToken);
            // Inside the try: getString() throws when the claim holds a
            // non-string, which is a bad token, not a server error.
            $identity = $claims->getString($this->identityClaim);
        } catch (JwtException $e) {
            throw new BadCredentialsException('Invalid access token.', previous: $e);
        }

        if (null === $identity || '' === $identity) {
            throw new BadCredentialsException(sprintf('Access token carries no "%s" claim to identify the user.', $this->identityClaim));
        }

        return new UserBadge($identity);
    }
}
