<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use Stringable;

/**
 * A minted access token and the lifetime it was actually minted with.
 *
 * The lifetime travels with the token because a caller that overrode the
 * configured TTL would otherwise have to remember what it asked for in order to
 * fill in an RFC 6750 `expires_in`, and because reading it back off the token
 * means parsing what was just built.
 */
final class IssuedToken implements Stringable
{
    public function __construct(
        public readonly string $value,
        public readonly int $expiresIn,
    ) {}

    public function __toString(): string
    {
        return $this->value;
    }
}
