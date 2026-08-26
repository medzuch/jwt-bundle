<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\Jwt\Jwt\ClaimsSet;

/**
 * A consumer accepted a token: it verified, it is addressed here, nobody has
 * withdrawn it, and it names somebody.
 *
 * "Verified", not "authenticated". Under `user.mode: provider` and `claims` the
 * badge carries a loader Symfony calls afterwards, so a token accepted here can
 * still fail the request because the store has no such user — `LoginSuccessEvent`
 * answers that, this does not.
 *
 * README "Knowing why, when the caller is not told" has the rest, including the
 * warning that the claims are the token's own and a listener logging them logs
 * whatever they hold.
 */
final class JwtVerifiedEvent
{
    public function __construct(
        public readonly string $consumer,
        public readonly ClaimsSet $claims,
        public readonly string $identifier,
    ) {}
}
