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
 * Listeners cannot change anything: the token exists by the time this is
 * dispatched. Changing what it says is what JwtIssuingEvent is for.
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
