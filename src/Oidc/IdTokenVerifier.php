<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Oidc;

use DateInterval;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\MediaType;
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
 *
 * **A token that says it is something else is refused before anything else.**
 * OIDC asks for no `typ` on an ID token, so the profile underneath checks none
 * — which means an access token would verify here whenever its `aud` happened
 * to equal this registration's `client_id`, and it says so on its own header.
 * That is the confusion in the direction the rest of this class guards the
 * other way: a credential minted for an API, presented at a login callback,
 * would log somebody in. A security event token is the same shape of mistake
 * and RFC 8417 §4 names it, so `secevent+jwt` is refused beside `at+jwt`. It
 * costs one header comparison per type, and no provider mints an ID token
 * labelled as either (RFC 8725 §3.11 asks producers to type explicitly, which
 * is what makes the label trustworthy where it appears).
 *
 * The comparison is `MediaType::equivalent()`, so every spelling RFC 7515
 * §4.1.9 makes equivalent is refused too — `application/AT+JWT` says `at+jwt`,
 * and a guard comparing strings would have taken it.
 */
final class IdTokenVerifier
{
    /**
     * The media types that say a token was minted for something else, and the
     * refusal each one earns. An ID token carries no `typ` of its own that
     * this could check for instead — OIDC asks for none — so the check is the
     * other way round: a token that names another profile is not this one,
     * whatever its claims would have satisfied.
     *
     * @var array<string, string>
     */
    private const NOT_AN_ID_TOKEN = [
        'at+jwt' => 'This is an access token (`typ: at+jwt`), not an ID token. An access token authorises a call to an API; an ID token says who authenticated to the client that asked for it, and accepting one for the other logs somebody in with a credential minted for something else.',
        'secevent+jwt' => 'This is a security event token (`typ: secevent+jwt`), not an ID token. A SET reports something that happened to a subject — an account disabled, a session revoked — and RFC 8417 §4 is about keeping the two apart; accepting one here would log somebody in with a notification about them.',
    ];

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
     *                      a `typ` naming another profile (`at+jwt`, `secevent+jwt`), or
     *                      signature, issuer, audience, `azp`, `nonce`, expiry or a missing
     *                      required claim
     */
    public function verify(string $idToken, ?string $nonce = null): ClaimsSet
    {
        self::assertNotAnotherProfilesToken($idToken);

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

    /**
     * Read from the header before the token is verified, which is where a
     * refusal on what a token says it is belongs: nothing is admitted by
     * reading it early, because everything below still runs on what survives.
     * An unparseable string falls through to the consumer, whose refusal names
     * what is actually wrong with it.
     *
     * @throws InvalidHeaderException
     */
    private static function assertNotAnotherProfilesToken(string $idToken): void
    {
        try {
            $type = JwtParser::parse($idToken)->header->type();
        } catch (JwtException) {
            return;
        }

        if (null === $type) {
            return;
        }

        foreach (self::NOT_AN_ID_TOKEN as $declared => $refusal) {
            // RFC 7515 §4.1.9 again: the `application/` prefix is optional and
            // the comparison is case-insensitive, so the library's own
            // normaliser decides rather than a string compare here.
            if (MediaType::equivalent($type, $declared)) {
                throw new InvalidHeaderException($refusal);
            }
        }
    }
}
