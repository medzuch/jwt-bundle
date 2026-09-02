<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Refresh;

use DateInterval;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * Mints the opaque half of a session (I9).
 *
 * 256 bits from `random_bytes()`, base64url-encoded so it survives a header, a
 * JSON body and a URL unescaped, paired with the SHA-256 an implementation of
 * {@see RefreshTokenStoreInterface} persists in its place. Both halves come
 * back in one {@see RefreshToken} because they are only ever known together,
 * for the length of one method call in the caller.
 *
 * The length is not configurable. 32 bytes is past the point where guessing is
 * the attack, and an option there would only ever be used to make a token
 * shorter — a setting whose safe value is its only value is documentation
 * pretending to be configuration.
 *
 * The lifetime is an argument rather than a setting for a different reason: it
 * belongs to the flow, not to the deployment. A "remember me" session and a
 * short-lived confidential-client session are minted by the same application
 * with different lifetimes, and a container-level default would make the
 * shorter one the exception.
 */
final class RefreshTokenGenerator
{
    private const BYTES = 32;

    public function __construct(private readonly ClockInterface $clock) {}

    /**
     * @param DateInterval $ttl how long the token stays acceptable, measured from now
     *
     * @throws InvalidArgumentException when `$ttl` is zero, negative or inverted: a token
     *                                  that expires no later than it is minted can never be spent
     */
    public function generate(DateInterval $ttl): RefreshToken
    {
        $now = $this->clock->now();
        $expiresAt = $now->add($ttl);

        if ($expiresAt <= $now) {
            throw new InvalidArgumentException('A refresh token needs a lifetime that ends after it starts; this one expires at or before the moment it is minted, so nothing could ever exchange it.');
        }

        // Base64url without padding: `=` is legal in a JSON string and illegal
        // unescaped in a query, and a token that has to be encoded differently
        // depending on where it travels is a token that gets compared in the
        // wrong form somewhere.
        $value = rtrim(strtr(base64_encode(random_bytes(self::BYTES)), '+/', '-_'), '=');

        return new RefreshToken($value, RefreshToken::hashOf($value), $expiresAt);
    }
}
