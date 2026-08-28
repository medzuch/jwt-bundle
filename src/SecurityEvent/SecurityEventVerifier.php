<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\SecurityEvent;

use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Profile\SetConsumer;

/**
 * Verifies an RFC 8417 Security Event Token from one configured transmitter (C8).
 *
 * Not a firewall authenticator, for the same reason {@see \Medzuch\JwtBundle\Oidc\IdTokenVerifier}
 * is not one: a SET is not a bearer credential and authenticates nobody. It
 * arrives in the body of a POST to a delivery endpoint (RFC 8935), describes
 * something that happened to a subject who is not the caller, and the right
 * answer to a good one is `202 Accepted` with no session created. README
 * "Sending and receiving security events" has the controller.
 *
 * The consumer behind this is built once, by the container, rather than per
 * call — which the ID-token verifier cannot do, because a nonce belongs to one
 * authentication request and would be fixed at deploy. A SET has no such value:
 * everything checked here is configuration, so there is nothing to defer.
 *
 * **A SET has no expiry, and this class does not invent one.** RFC 8417 §4.1.4
 * makes `exp` not meaningful, so a verified SET stays verifiable for as long as
 * the signing key does, and a transmitter's replayed delivery verifies exactly
 * like the first one. Detecting that is the receiver's, on the `jti` every SET
 * is required to carry (§2.2). This bundle's denylist is not the seam for it —
 * {@see \Medzuch\JwtBundle\Revocation\TokenDenylistInterface::revoke()} takes
 * the moment an entry may be forgotten, which for an access token is its `exp`
 * and for a SET is nothing at all. README says what to store instead.
 */
final class SecurityEventVerifier
{
    public function __construct(private readonly SetConsumer $consumer) {}

    /**
     * @throws JwtException when the token is not a valid SET from this transmitter:
     *                      signature, issuer, audience, the `secevent+jwt` type, a missing required
     *                      claim, or an `events` object that is absent, empty or not an object
     */
    public function verify(string $securityEventToken): ClaimsSet
    {
        return $this->consumer->parse($securityEventToken);
    }
}
