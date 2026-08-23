<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\JwtBundle\DataCollector\JwtDataCollector;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Wraps a consumer's handler so the profiler can say what happened.
 *
 * A decorator rather than another event, because the panel wants what the
 * events deliberately do not carry: the header the token named, and how long
 * the verifying took. Both belong to the call, not to its verdict, and putting
 * them on {@see \Medzuch\JwtBundle\Event\JwtVerifiedEvent} would be widening a
 * public contract to feed a development tool.
 *
 * Registered only where a profiler is, so nothing here runs in production.
 *
 * @internal
 */
final class TraceableAccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private readonly AccessTokenHandlerInterface $handler,
        private readonly string $consumer,
        private readonly JwtDataCollector $collector,
    ) {}

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        $started = hrtime(true);
        [$algorithm, $keyId, $claims] = self::describe($accessToken);

        try {
            $badge = $this->handler->getUserBadgeFrom($accessToken);
        } catch (AuthenticationException $refusal) {
            $this->collector->refused(
                $this->consumer,
                $refusal instanceof RejectedTokenException ? $refusal->reason : null,
                self::detail($refusal),
                $algorithm,
                $keyId,
                self::since($started),
                $claims,
            );

            throw $refusal;
        }

        $this->collector->accepted($this->consumer, $badge->getUserIdentifier(), $claims, $algorithm, $keyId, self::since($started));

        return $badge;
    }

    /**
     * The header and the claims as the token itself has them — unverified, and
     * shown for the same reason the panel exists: a token this consumer refused
     * has no verified claims to show, and what it *said* is exactly what its
     * reader needs to see.
     *
     * @return array{string|null, string|null, array<string, mixed>}
     */
    private static function describe(string $token): array
    {
        try {
            $parsed = JwtParser::parse($token);
        } catch (JwtException) {
            // Not a JWT at all, which the panel shows as the refusal it caused.
            return [null, null, []];
        }

        return [$parsed->header->algorithm(), $parsed->header->keyId(), $parsed->unverifiedClaims->all()];
    }

    /**
     * The library's account of the failure where there is one: a
     * `BadCredentialsException` carries the generic message the wire gets, and
     * the sentence worth reading is underneath it.
     */
    private static function detail(AuthenticationException $refusal): string
    {
        return $refusal->getPrevious()?->getMessage() ?? $refusal->getMessage();
    }

    private static function since(float|int $started): float
    {
        return (hrtime(true) - $started) / 1_000_000;
    }
}
