<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwe\CompactSerializer as JweCompactSerializer;
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
        [$algorithm, $keyId, $claims, $encryption] = self::describe($accessToken);
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
                $encryption,
            );

            throw $failure;
        }

        $this->collector->accepted($this->consumer, $badge->getUserIdentifier(), $claims, $algorithm, $keyId, self::since($started), $encryption);

        return $badge;
    }

    /**
     * The header and the claims as the token itself has them — unverified, and
     * shown for the same reason the panel exists: a token this consumer refused
     * has no verified claims to show, and what it *said* is exactly what its
     * reader needs to see.
     *
     * An encrypted token (C12) has an outer header that reads without a key and
     * claims that do not, so it answers with the first and an empty second. The
     * `enc` it comes back with is what tells the panel those two facts apart —
     * without it, a token this consumer decrypted and accepted would be shown
     * under the sentence reserved for something that is not a JWT at all.
     *
     * This runs on the bearer string before the handler is called, so the
     * claims inside an encrypted token are not available here even where the
     * consumer went on to read them: the key belongs to the consumer, and a
     * decorator that decrypted a second time to fill in a panel would be doing
     * the expensive half of the work twice on every profiled request.
     *
     * @return array{string|null, string|null, array<string, mixed>, string|null}
     */
    private static function describe(string $token): array
    {
        try {
            $parsed = JwtParser::parse($token);

            return [$parsed->header->algorithm(), $parsed->header->keyId(), $parsed->unverifiedClaims->all(), null];
        } catch (JwtException) {
        }

        try {
            $jwe = JweCompactSerializer::deserialize($token);
        } catch (JwtException) {
            // Not a JWT at all, which the panel shows as the refusal it caused.
            return [null, null, [], null];
        }

        return [self::headerString($jwe->header, 'alg'), self::headerString($jwe->header, 'kid'), [], self::headerString($jwe->header, 'enc')];
    }

    /**
     * A JWE header is a plain array rather than the library's `Header`, so
     * reading a member out of it is a narrowing rather than a property access.
     * The serializer has already refused a non-string `alg`, `enc` or `kid`, so
     * the only value this really answers for is an absent one — a token naming
     * no key, which is how a single-key consumer works. The library narrows the
     * same three members the same way, in the same place, for the same reason.
     *
     * @param array<string, mixed> $header
     */
    private static function headerString(array $header, string $name): ?string
    {
        $value = $header[$name] ?? null;

        return is_string($value) ? $value : null;
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
