<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\ClaimValidationException;
use Medzuch\Jwt\Exception\DecryptionException;
use Medzuch\Jwt\Exception\ExpiredException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Exception\InvalidIssuerException;
use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Exception\InvalidTypeException;
use Medzuch\Jwt\Exception\IssuedInFutureException;
use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Exception\KeyMismatchException;
use Medzuch\Jwt\Exception\KeyNotFoundException;
use Medzuch\Jwt\Exception\MalformedJwtException;
use Medzuch\Jwt\Exception\NotYetValidException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Why a consumer refused a token, in the vocabulary metrics and alerting need.
 *
 * Deliberately coarser than the library's exception hierarchy. An application
 * counting refusals wants a handful of stable buckets, and a case per exception
 * class would only move the coupling: the library could add a leaf tomorrow and
 * every dashboard built on this would need to learn its name.
 *
 * The distinctions kept are the ones an operator acts on differently. An
 * expired token is the normal cost of short lifetimes; a bad signature is
 * someone trying something; an unknown key is usually a rotation that has not
 * finished; and {@see self::KeysUnavailable} is not a bad token at all but an
 * issuer this application cannot reach, which is an outage and should page
 * somebody.
 */
enum RejectionReason: string
{
    /** `exp` has passed — the ordinary refusal, and the one worth a baseline. */
    case Expired = 'expired';

    /** `nbf` or `iat` puts the token in the future: clock skew, usually. */
    case NotYetValid = 'not_yet_valid';

    /**
     * `exp` is still in the future and the token is older than this consumer
     * accepts. Kept apart from {@see self::Expired} because they are different
     * facts about different clocks: one is the issuer's lifetime running out,
     * the other is this application refusing a lifetime the issuer thought
     * reasonable.
     */
    case TooOld = 'too_old';

    /** The signature does not verify under a key this consumer accepts. */
    case SignatureInvalid = 'signature_invalid';

    /**
     * The outer layer of an encrypted token would not open: it was not
     * encrypted to a key this consumer holds, or the ciphertext has been
     * altered since it was written and the AEAD tag says so.
     *
     * Kept apart from {@see self::SignatureInvalid} because they fail in
     * different halves of the pipeline and are fixed by different people. A
     * bad signature is a token somebody minted wrong or forged; this is a
     * sender and a receiver disagreeing about which key is current.
     */
    case DecryptionFailed = 'decryption_failed';

    /** No key matched the token's `kid`: a rotation half-done, or another issuer's token. */
    case UnknownKey = 'unknown_key';

    /** The token names an algorithm this consumer does not allow (RFC 8725 §3.1). */
    case AlgorithmRefused = 'algorithm_refused';

    /** `iss` is not the issuer this consumer trusts. */
    case WrongIssuer = 'wrong_issuer';

    /** `aud` does not name this consumer, or names someone else it refuses to share with. */
    case WrongAudience = 'wrong_audience';

    /** A denylist says this `jti` is withdrawn. */
    case Revoked = 'revoked';

    /** Not a JWT this consumer can read at all: structure, encoding, or `typ`. */
    case Malformed = 'malformed';

    /** A claim is missing, of the wrong type, or refused by the profile. */
    case ClaimsRefused = 'claims_refused';

    /**
     * The keys to verify with could not be had: the set would not fetch, or
     * what came back is not usable key material. An outage on one side or the
     * other, not a verdict on the token.
     */
    case KeysUnavailable = 'keys_unavailable';

    /** The token verified, and the application refused the identity behind it. */
    case IdentityRefused = 'identity_refused';

    /** A failure this bundle has no bucket for; the exception on the event says more. */
    case Other = 'other';

    /**
     * The reason a refusal carries, wherever it is read from.
     *
     * One place, because there are two readers — the handler, which announces
     * it on {@see \Medzuch\JwtBundle\Event\JwtRejectedEvent}, and the
     * profiler's decorator, which shows it. They disagreed once: an identity
     * refusal reached the event as `identity_refused` and the panel as
     * "other", because the handler rethrows the resolver's own exception and
     * the decorator asked a narrower question of it.
     */
    public static function forRefusal(AuthenticationException $failure): self
    {
        // Not one of ours means it came from the user resolver, which only runs
        // on a token that already verified.
        return $failure instanceof RejectedTokenException ? $failure->reason : self::IdentityRefused;
    }

    /**
     * The bucket a library failure belongs in.
     *
     * Ordered so that a leaf is matched before the abstract class it extends —
     * every claim failure is a {@see ClaimValidationException}, so that one
     * answers last.
     */
    public static function of(JwtException $failure): self
    {
        return match (true) {
            $failure instanceof ExpiredException => self::Expired,
            $failure instanceof NotYetValidException,
            $failure instanceof IssuedInFutureException => self::NotYetValid,
            $failure instanceof SignatureVerificationException => self::SignatureInvalid,
            $failure instanceof DecryptionException => self::DecryptionFailed,
            $failure instanceof KeyNotFoundException,
            $failure instanceof KeyMismatchException => self::UnknownKey,
            // Not a rotation half-done but key material that cannot be used —
            // a JWK the issuer published wrong, most likely. An operator
            // watching for "we cannot verify anything right now" should see it
            // beside an unreachable issuer, not beside a token naming a kid we
            // have not got yet.
            $failure instanceof InvalidKeyException => self::KeysUnavailable,
            $failure instanceof AlgorithmNotAllowedException => self::AlgorithmRefused,
            $failure instanceof InvalidIssuerException => self::WrongIssuer,
            $failure instanceof InvalidAudienceException => self::WrongAudience,
            $failure instanceof JwksResolutionException => self::KeysUnavailable,
            $failure instanceof MalformedJwtException,
            $failure instanceof InvalidHeaderException,
            // Well-formed, and not the kind of token this consumer reads — an
            // ID token presented as an access token, most often. The same
            // bucket as garbage: both mean the client sent the wrong thing.
            $failure instanceof InvalidTypeException => self::Malformed,
            $failure instanceof ClaimValidationException => self::ClaimsRefused,
            default => self::Other,
        };
    }
}
