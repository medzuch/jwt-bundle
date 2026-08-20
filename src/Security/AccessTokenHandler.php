<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Profile\ProfileConsumer;
use Medzuch\JwtBundle\Security\Identity\UserResolverInterface;
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
 * identity somewhere else entirely. What that identifier then becomes is a
 * {@see UserResolverInterface}: a lookup in the application's store, a user
 * built from the claims, or the application's own mapping.
 *
 * The audience check the library makes is the one RFC 7519 §4.1.3 describes:
 * a token is for us if `aud` names us, whoever else it also names. An
 * `exclusive` consumer adds the other half — that it names nobody else — which
 * RFC 9068 §3 asks of access tokens and which is not the same question.
 */
final class AccessTokenHandler implements AccessTokenHandlerInterface
{
    /**
     * @param list<string>|null $exclusiveTo audiences this consumer answers to, when a token
     *                                       naming any other is to be refused. Null accepts a
     *                                       token addressed to us among others.
     */
    public function __construct(
        private readonly ProfileConsumer $consumer,
        private readonly string $identityClaim,
        private readonly UserResolverInterface $users,
        private readonly ?array $exclusiveTo = null,
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

        $this->assertAddressedToNobodyElse($claims->audience());

        if (null === $identity || '' === $identity) {
            throw new BadCredentialsException(sprintf('Access token carries no "%s" claim to identify the user.', $this->identityClaim));
        }

        return $this->users->badgeFor($identity, $claims);
    }

    /**
     * A token minted for several services is valid at each of them, so it only
     * has to leak from the least careful one to be presented here. Refusing it
     * is a posture, not a correctness fix — the token is a valid token for us —
     * which is why it is opt-in per consumer and off by default.
     *
     * @param list<string> $audience
     */
    private function assertAddressedToNobodyElse(array $audience): void
    {
        if (null === $this->exclusiveTo) {
            return;
        }

        $others = array_values(array_diff($audience, $this->exclusiveTo));

        if ([] !== $others) {
            throw new BadCredentialsException(sprintf(
                'Access token is addressed to %s as well, and this consumer accepts tokens minted for it alone.',
                '"' . implode('", "', $others) . '"',
            ));
        }
    }
}
