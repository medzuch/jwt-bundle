<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Profile\ProfileConsumer;
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;
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
 * Who the token names, and what that identity becomes, is a
 * {@see UserResolverInterface}: a lookup in the application's store, a user
 * built from the claims, or the application's own mapping — which may derive an
 * identity the token carries in no single claim.
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
        private readonly UserResolverInterface $users,
        private readonly ?array $exclusiveTo = null,
        private readonly ?TokenDenylistInterface $denylist = null,
    ) {}

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        try {
            $claims = $this->consumer->parse($accessToken);

            $this->assertAddressedToNobodyElse($claims->audience());
            $this->assertNotRevoked($claims->jwtId());

            // Inside the try because naming the user reads claims, and
            // getString() throws when one holds a non-string — a bad token,
            // not a server error. A BadCredentialsException raised in there is
            // not a JwtException and passes through with its own message.
            return $this->users->badgeFor($claims);
        } catch (JwtException $e) {
            throw new BadCredentialsException('Invalid access token.', previous: $e);
        }
    }

    /**
     * A verified token is one nobody has withdrawn since. Only asked when a
     * denylist is configured, because the alternative — a lookup that always
     * answers "not revoked" — is a cache round trip per request buying nothing.
     */
    private function assertNotRevoked(?string $jti): void
    {
        if (null === $this->denylist) {
            return;
        }

        // RFC 9068 §2.2 makes `jti` required and the profile enforces it, so
        // this is unreachable through the access-token path. It is here because
        // "no id" and "not revoked" are different answers, and a denylist that
        // silently accepted the first would be a revocation list that lets
        // through exactly the tokens nobody can name.
        if (null === $jti || '' === $jti) {
            throw new BadCredentialsException('Access token carries no "jti", so it cannot be checked against the denylist.');
        }

        if ($this->denylist->isRevoked($jti)) {
            throw new BadCredentialsException('Access token has been revoked.');
        }
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
