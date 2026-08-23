<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\JwtBundle\Issuer\TokenIssuance;

/**
 * Dispatched once a token is signed: the audit record of something this
 * application granted.
 *
 * It carries no token. Everything an audit trail needs is here — who it was
 * for, what it grants, how long it lives, and the `jti` that names it — and a
 * listener writing this to a log would otherwise be writing a working
 * credential to a log. Revocation needs the `jti`, not the token, and so does
 * anything else that asks about it later.
 *
 * Two of its fields answer different questions, and for one token they can
 * disagree: `$issuance->scopes` is what the call asked to grant, while a
 * `scope` in `$claims` — which configuration and the `issue()` argument are
 * still allowed to set — is what the token actually says. An audit trail that
 * has to match the token reads the claim.
 *
 * Listeners cannot change anything: the token exists by the time this is
 * dispatched. Changing what it says is what JwtIssuingEvent is for.
 *
 * **Dispatched after signing**, which decides what a throwing listener means:
 * the token exists, is signed, and will verify until `exp`, while the caller of
 * `issue()` sees an exception. Nothing has been issued to anybody, so nothing
 * is exposed — but an application treating a failed `issue()` as "no token
 * exists" is wrong, and one that needs the opposite guarantee, no token without
 * its audit record, cannot have it from an event dispatched here. That would
 * take an audit write before signing, which is the application's own to make in
 * a JwtIssuingEvent listener.
 */
final class JwtIssuedEvent
{
    /**
     * @param array<string, mixed> $claims the claims contributed on top of the profile's own
     */
    public function __construct(
        public readonly TokenIssuance $issuance,
        public readonly array $claims,
    ) {}
}
