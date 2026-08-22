<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Throwable;

/**
 * A refusal that knows why, so the reason survives the trip to a listener.
 *
 * A `BadCredentialsException` and treated as one: `getMessageKey()` is
 * inherited, so what reaches the caller is still Symfony's generic "Invalid
 * credentials." and none of the detail below it. The reason is for the log, the
 * metric and {@see \Medzuch\JwtBundle\Event\JwtRejectedEvent} — never for the
 * wire (RFC 6750 §3.1 has three error codes, and "which claim" is not among
 * them).
 */
final class RejectedTokenException extends BadCredentialsException
{
    public function __construct(
        public readonly RejectionReason $reason,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, previous: $previous);
    }
}
