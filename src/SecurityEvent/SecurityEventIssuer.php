<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\SecurityEvent;

use Medzuch\Jwt\Profile\SetBuilder;
use Medzuch\Jwt\Profile\SetProfile;

/**
 * Mints RFC 8417 Security Event Tokens for one configured stream (I7).
 *
 * README "Sending and receiving security events" says what a SET is for. What
 * it is *not* is the reason this class hands back a builder instead of a token:
 * a SET is not a credential. There is no subject to mint it for and no lifetime
 * to give it — RFC 8417 §4.1.4 says `exp` is not meaningful, because a security
 * event is a statement that something happened, not a permission that lapses.
 * What varies between two SETs from the same stream is the events themselves,
 * and no argument list this bundle could invent would express those better than
 * the library's own builder.
 *
 * So the profile supplies `iss`, `iat`, `jti` and the `secevent+jwt` type, this
 * adds the configured audience, and the caller declares the events and calls
 * `build()`.
 *
 * The issuance events {@see \Medzuch\JwtBundle\Event\JwtIssuingEvent} and
 * {@see \Medzuch\JwtBundle\Event\JwtIssuedEvent} are deliberately not dispatched
 * here: both carry a {@see \Medzuch\JwtBundle\Issuer\TokenIssuance}, whose shape
 * is an access token's — subject, scopes, audience, TTL — and a SET has none of
 * those. A listener written for access tokens would be handed a value it cannot
 * read, which is worse than not being called.
 */
final class SecurityEventIssuer
{
    /**
     * @param list<string> $audience the recipients every SET from this stream names,
     *                               or an empty list to leave `aud` to the caller. RFC 8417 §2.2 only
     *                               RECOMMENDS it, and a stream with one subscriber is the case where
     *                               configuring it is right
     */
    public function __construct(
        private readonly SetProfile $profile,
        private readonly array $audience = [],
    ) {}

    /**
     * A builder with everything the stream fixes already applied.
     *
     * Declare at least one event on it — the library refuses a SET without one
     * (§2.2) — and call `build()`:
     *
     * ```php
     * $set = $issuer->issue()
     *     ->subject('user-42')
     *     ->event('https://schemas.openid.net/secevent/risc/event-type/account-disabled', [
     *         'reason' => 'hijacking',
     *     ])
     *     ->build();
     * ```
     */
    public function issue(): SetBuilder
    {
        $builder = $this->profile->issue();

        return [] === $this->audience ? $builder : $builder->audience($this->audience);
    }
}
