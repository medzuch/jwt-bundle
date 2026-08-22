<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\JwtBundle\Security\RejectionReason;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * A consumer refused a token, and this says which consumer and why.
 *
 * Symfony's own `LoginFailureEvent` reaches a listener too, carrying a
 * `BadCredentialsException` whose message is the same generic string for every
 * refusal — which is right on the wire and useless for a dashboard. The reason
 * here is the missing half: expired, badly signed, addressed elsewhere,
 * revoked, or an issuer that could not be reached at all.
 *
 * It carries no token. What was presented is a credential whether or not it
 * verified — a revoked token still opens doors elsewhere, and a merely expired
 * one says who its subject was — so a listener logging what it is handed cannot
 * write one to a log. `$cause` names the specific failure for anyone who needs
 * more than the bucket.
 *
 * Dispatched for what the token was, not for what became of the user: with
 * `user.mode: provider` or `claims` the identity is loaded after this bundle is
 * done, and a user that turns out not to exist is Symfony's `LoginFailureEvent`
 * to report.
 */
final class JwtRejectedEvent
{
    public function __construct(
        public readonly string $consumer,
        public readonly RejectionReason $reason,
        public readonly AuthenticationException $cause,
    ) {}
}
