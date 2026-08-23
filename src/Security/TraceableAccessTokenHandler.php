<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\JwtBundle\DataCollector\JwtDataCollector;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Throwable;

/**
 * Wraps a consumer's handler so the profiler can say what happened.
 *
 * A decorator rather than another event, because the panel wants what the
 * events deliberately do not carry: the header the token named, and how long
 * the verifying took. Both belong to the call, not to its verdict, and putting
 * them on {@see \Medzuch\JwtBundle\Event\JwtVerifiedEvent} would be widening a
 * public contract to feed a development tool.
 *
 * Registered wherever a profiler service is, which is where the panel can be
 * read — an environment rather than a rule: a staging deployment with the
 * profiler on gets the wrapper too, and one without it never builds this class
 * at all.
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
        // Described first, then timed: reading the header is work the profiler
        // asked for, and a duration presented as "spent verifying" should not
        // include the decorator that measured it.
        [$algorithm, $keyId, $claims] = self::describe($accessToken);
        $started = hrtime(true);

        try {
            $badge = $this->handler->getUserBadgeFrom($accessToken);
        } catch (Throwable $failure) {
            // Throwable, not AuthenticationException: a resolver or a denylist
            // store that throws on its own account is precisely the request
            // somebody opens the panel to understand, and it would otherwise be
            // the one request with no row at all.
            $this->collector->refused(
                $this->consumer,
                $failure instanceof AuthenticationException ? RejectionReason::forRefusal($failure) : null,
                self::detail($failure),
                $algorithm,
                $keyId,
                self::since($started),
                $claims,
            );

            throw $failure;
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
    private static function detail(Throwable $failure): string
    {
        return $failure->getPrevious()?->getMessage() ?? $failure->getMessage();
    }

    private static function since(float|int $started): float
    {
        return (hrtime(true) - $started) / 1_000_000;
    }
}
