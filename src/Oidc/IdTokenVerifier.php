<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Oidc;

use DateInterval;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\KeyResolver;
use Medzuch\Jwt\Profile\IdTokenProfile;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

/**
 * Verifies an OIDC ID token for one relying-party registration.
 *
 * Not a firewall authenticator (DEC-8), and README "Verifying an ID token (OIDC
 * relying party)" says why that matters to whoever writes the callback: an ID
 * token is not a bearer credential for an API.
 *
 * A consumer per call rather than one built at container time, because of the
 * nonce: the library binds it when the consumer is built, so a container-built
 * consumer could only ever check a value fixed at deploy — which is not a
 * nonce. What does not change is what the container holds.
 */
final class IdTokenVerifier
{
    /**
     * @param non-empty-list<SigningAlgorithm> $allowedAlgorithms
     */
    public function __construct(
        private readonly string $issuer,
        private readonly string $clientId,
        private readonly JwkSet|KeyResolver $keys,
        private readonly array $allowedAlgorithms,
        private readonly ?ClockInterface $clock = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?DateInterval $leeway = null,
        private readonly ?LogLevels $logLevels = null,
    ) {}

    /**
     * @param string|null $nonce the value bound to the authentication request.
     *                           Null skips the check, which is right only for a flow that sent no
     *                           nonce — an authorization-code flow that did and then does not check
     *                           has no replay defence (OIDC Core §3.1.3.7).
     *
     * @throws JwtException when the token is not a valid ID token for this registration:
     *                      signature, issuer, audience, `azp`, `nonce`, expiry or a missing required claim
     */
    public function verify(string $idToken, ?string $nonce = null): ClaimsSet
    {
        return IdTokenProfile::consumer(
            $this->issuer,
            $this->clientId,
            $this->keys,
            $this->allowedAlgorithms,
            $nonce,
            $this->clock,
            $this->logger,
            $this->logLevels,
            $this->leeway,
        )->parse($idToken);
    }
}
