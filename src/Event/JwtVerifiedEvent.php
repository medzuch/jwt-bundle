<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\Jwt\Jwt\ClaimsSet;

/**
 * A consumer accepted a token: it verified, it is addressed here, nobody has
 * withdrawn it, and it names somebody.
 *
 * "Verified", not "authenticated". In `user.mode: provider` and `claims` the
 * badge carries a loader Symfony calls afterwards, so a token can be accepted
 * here and the request still fail because the store has no such user — which is
 * `LoginSuccessEvent`'s question, not this one's. What this event is good for is
 * the other half: how many tokens each consumer accepts, from which issuer,
 * with what left of their lifetime.
 *
 * The claims are the token's own, so a listener can read anything it carries.
 * `$identifier` is what the request will authenticate as, which is not always a
 * claim: a `custom` factory may derive it from several.
 */
final class JwtVerifiedEvent
{
    public function __construct(
        public readonly string $consumer,
        public readonly ClaimsSet $claims,
        public readonly string $identifier,
    ) {}
}
