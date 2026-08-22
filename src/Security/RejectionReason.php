<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\Jwt\Exception\AlgorithmNotAllowedException;
use Medzuch\Jwt\Exception\ClaimValidationException;
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

    /** The signature does not verify under a key this consumer accepts. */
    case SignatureInvalid = 'signature_invalid';

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

    /** The key set could not be fetched. An outage, not a verdict on the token. */
    case KeysUnavailable = 'keys_unavailable';

    /** The token verified, and the application refused the identity behind it. */
    case IdentityRefused = 'identity_refused';

    /** A failure this bundle has no bucket for; the exception on the event says more. */
    case Other = 'other';

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
            $failure instanceof KeyNotFoundException,
            $failure instanceof KeyMismatchException => self::UnknownKey,
            $failure instanceof InvalidKeyException => self::UnknownKey,
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
