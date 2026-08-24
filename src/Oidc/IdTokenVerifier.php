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
 * **Not a firewall authenticator, deliberately.** An ID token says who
 * authenticated to the client that requested it; it is not a bearer credential
 * for an API, and accepting one as such is the confusion RFC 9068 exists to
 * end — a token minted for a browser session would authorise a machine call.
 * So the bundle registers no `access_token` handler for it: the application
 * calls this service where it already is, in its OIDC callback, and decides
 * what a verified `sub` means locally.
 *
 * The `nonce` is a per-request value, bound to one authentication request and
 * kept by the application (in the session, usually) until the callback comes
 * back. The library binds it when the consumer is built, so a consumer built
 * once at container time could only ever check a nonce fixed at deploy — which
 * is not a nonce. Hence a consumer per call, with the value the application
 * has, and the container holding what does not change.
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
