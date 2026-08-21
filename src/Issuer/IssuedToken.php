<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use Stringable;

/**
 * A minted access token, the lifetime it was actually minted with, and the id
 * it can later be named by.
 *
 * Both travel with the token for the same reason: a caller that overrode the
 * configured TTL would otherwise have to remember what it asked for in order to
 * fill in an RFC 6750 `expires_in`, and an application that may need to revoke
 * this token would have to parse what was just built to learn its `jti`.
 */
final class IssuedToken implements Stringable
{
    public function __construct(
        public readonly string $value,
        public readonly int $expiresIn,
        public readonly string $jti,
    ) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
