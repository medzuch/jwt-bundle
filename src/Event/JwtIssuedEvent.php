<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\JwtBundle\Issuer\TokenIssuance;

/**
 * Dispatched once a token is signed: the audit record of something this
 * application granted.
 *
 * It carries no token. Everything an audit trail needs is on the event, and the
 * `jti` is what revocation and anything else asking later will want. Listeners
 * cannot change what was issued — {@see JwtIssuingEvent} is where that happens.
 *
 * README "Knowing what was issued" has the rest: what a throwing listener means
 * for a token that already exists, and when an audit trail should read
 * `claims['scope']` rather than `issuance->scopes`.
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
