<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Profile\ProfileConsumer;
use Medzuch\JwtBundle\Event\JwtRejectedEvent;
use Medzuch\JwtBundle\Event\JwtVerifiedEvent;
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;
use Medzuch\JwtBundle\Security\Identity\UserResolverInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Turns a validated token into a `UserBadge` for Symfony's native
 * `access_token` authenticator. One instance per configured consumer.
 *
 * Every failure becomes the same `BadCredentialsException`, carrying the
 * original as `previous` and a {@see RejectionReason} of its own: what refused
 * the token belongs in the log and on {@see JwtRejectedEvent}, not in the
 * response, where RFC 6750 §3.1 has three error codes and "which claim" is not
 * among them. A token that is accepted announces itself too, on
 * {@see JwtVerifiedEvent} — both are dispatched only where an application has
 * an event dispatcher, which outside a framework it may not.
 *
 * Who the token names, and what that identity becomes, is a
 * {@see UserResolverInterface}: a lookup in the application's store, a user
 * built from the claims, or the application's own mapping — which may derive an
 * identity the token carries in no single claim.
 *
 * The audience check the library makes is the one RFC 7519 §4.1.3 describes:
 * a token is for us if `aud` names us, whoever else it also names. An
 * `exclusive` consumer adds the other half — that it names nobody else — which
 * RFC 9068 §3 asks of access tokens and which is not the same question.
 *
 * @internal
 */
final class AccessTokenHandler implements AccessTokenHandlerInterface
{
    /**
     * @param list<string>|null $exclusiveTo   audiences this consumer answers to, when a token
     *                                         naming any other is to be refused. Null accepts a
     *                                         token addressed to us among others.
     * @param int|null          $maxTokenAge   seconds since `iat` after which a token is refused
     *                                         whatever its `exp` says. Null asks nothing.
     * @param int               $leewaySeconds the consumer's clock-skew tolerance, which widens
     *                                         the age window for the same reason it widens `exp`
     */
    public function __construct(
        private readonly ProfileConsumer $consumer,
        private readonly string $name,
        private readonly UserResolverInterface $users,
        private readonly ClockInterface $clock,
        private readonly ?array $exclusiveTo = null,
        private readonly ?int $maxTokenAge = null,
        private readonly int $leewaySeconds = 0,
        private readonly ?TokenDenylistInterface $denylist = null,
        private readonly ?EventDispatcherInterface $events = null,
    ) {}

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        try {
            $claims = $this->consumer->parse($accessToken);

            $this->assertAddressedToNobodyElse($claims->audience());
            $this->assertFreshEnough($claims->issuedAt());
            $this->assertNotRevoked($claims->jwtId());

            // Inside the try because naming the user reads claims, and
            // getString() throws when one holds a non-string — a bad token,
            // not a server error. An AuthenticationException raised in there is
            // not a JwtException and passes through with its own message.
            $badge = $this->users->badgeFor($claims);
        } catch (JwtException $e) {
            throw $this->rejected(new RejectedTokenException(RejectionReason::of($e), 'Invalid access token.', $e));
        } catch (AuthenticationException $e) {
            throw $this->rejected($e);
        }

        $this->events?->dispatch(new JwtVerifiedEvent($this->name, $claims, $badge->getUserIdentifier()));

        return $badge;
    }

    /**
     * Announces a refusal and hands back the exception to throw, so that one
     * `throw` site is one event: a refusal raised inside the try would
     * otherwise be caught by the block below it and announced twice.
     *
     * An exception that is not ours came from the user resolver, which only
     * runs on a token that already verified — the token was fine and the
     * application refused what it named.
     */
    private function rejected(AuthenticationException $failure): AuthenticationException
    {
        $this->events?->dispatch(new JwtRejectedEvent($this->name, RejectionReason::forRefusal($failure), $failure));

        return $failure;
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
            throw new RejectedTokenException(RejectionReason::ClaimsRefused, 'Access token carries no "jti", so it cannot be checked against the denylist.');
        }

        if ($this->denylist->isRevoked($jti)) {
            throw new RejectedTokenException(RejectionReason::Revoked, 'Access token has been revoked.');
        }
    }

    /**
     * A ceiling of this application's own on how long ago a token was minted.
     *
     * `exp` is the issuer's decision and this is ours, so the two are separate
     * refusals: a token can be well inside its lifetime and still be older than
     * a request here is willing to trust. What it buys is blast radius — a
     * token that leaked stops working when this runs out rather than when an
     * issuer who mints twenty-four-hour tokens decided it should.
     *
     * Leeway widens it, for the same reason the library applies leeway to `iat`
     * itself: the two clocks are not the same clock, and an age computed across
     * them inherits the skew.
     */
    private function assertFreshEnough(?DateTimeImmutable $issuedAt): void
    {
        if (null === $this->maxTokenAge) {
            return;
        }

        // RFC 9068 §2.2 makes `iat` required and the profile enforces it, so
        // this is unreachable through the access-token path — and it is here
        // for the reason the `jti` guard is: "no issuing time" and "young
        // enough" are different answers, and reading the first as the second
        // would exempt exactly the tokens whose age cannot be checked.
        if (null === $issuedAt) {
            throw new RejectedTokenException(RejectionReason::ClaimsRefused, 'Access token carries no "iat", so its age cannot be checked.');
        }

        $oldestAccepted = $this->clock->now()->sub(new DateInterval(sprintf('PT%dS', $this->maxTokenAge + $this->leewaySeconds)));

        if ($issuedAt < $oldestAccepted) {
            throw new RejectedTokenException(RejectionReason::TooOld, sprintf(
                'Access token was issued at %s and this consumer accepts none older than %d seconds.',
                $issuedAt->format(DateTimeImmutable::ATOM),
                $this->maxTokenAge,
            ));
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
            throw new RejectedTokenException(RejectionReason::WrongAudience, sprintf(
                'Access token is addressed to %s as well, and this consumer accepts tokens minted for it alone.',
                '"' . implode('", "', $others) . '"',
            ));
        }
    }
}
