<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\JwtBundle\Security\RejectionReason;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * A consumer refused a token, and this says which consumer and why.
 *
 * README "Knowing why, when the caller is not told" has the reasons and what
 * each usually means. Symfony's own `LoginFailureEvent` carries the same
 * generic `BadCredentialsException` for every refusal — right on the wire,
 * useless on a dashboard — and this is the missing half.
 *
 * It carries no token, and that is not only about logs: what was presented is a
 * credential whether or not it verified, since a revoked token still opens
 * doors elsewhere and a merely expired one still says who its subject was.
 */
final class JwtRejectedEvent
{
    public function __construct(
        public readonly string $consumer,
        public readonly RejectionReason $reason,
        public readonly AuthenticationException $cause,
    ) {}
}
