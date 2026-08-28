<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\SecurityEvent;

use DateInterval;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Profile\SetProfile;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

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
 * Built once per stream rather than per call, unlike the ID-token verifier:
 * nothing here is bound to a single request the way a nonce is.
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
    /**
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms
     * @param string|null                      $audience the `aud` a SET must name to be for this
     *                                                   receiver, or null to accept whatever it names. RFC 8417 §2.2
     *                                                   RECOMMENDS the claim; a transmitter feeding several receivers
     *                                                   from one stream is why checking it here is worth configuring
     */
    public function __construct(
        private readonly string $issuer,
        private readonly JwkSet|KeyResolver $keys,
        private readonly array $allowedAlgorithms,
        private readonly ?string $audience = null,
        private readonly ?ClockInterface $clock = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?DateInterval $leeway = null,
        private readonly ?LogLevels $logLevels = null,
    ) {}

    /**
     * @throws JwtException when the token is not a valid SET from this transmitter:
     *                      signature, issuer, audience, the `secevent+jwt` type, a missing required
     *                      claim, or an `events` object that is absent, empty or not an object
     */
    public function verify(string $securityEventToken): ClaimsSet
    {
        return SetProfile::consumer(
            $this->issuer,
            $this->keys,
            $this->allowedAlgorithms,
            $this->audience,
            $this->clock,
            $this->logger,
            $this->logLevels,
            $this->leeway,
        )->parse($securityEventToken);
    }
}
