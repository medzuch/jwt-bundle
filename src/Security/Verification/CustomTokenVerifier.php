<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Verification;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\Validator;

/**
 * A consumer for a `typ` this application defined, assembled from the library's
 * lower-level API rather than from a profile. The three profiles are the
 * standardised postures, and there is deliberately no fourth: a token type only
 * this application knows has no posture to standardise.
 *
 * One thing differs from a profile consumer, and it is the sort that is noticed
 * during an incident. The `Validator` carries the logger, so claim and crypto
 * outcomes are logged exactly as on the other path — but a token too malformed
 * to parse at all is not, because that happens before the validator sees it and
 * the profile's own `parse()` is where the equivalent logging lives. The
 * refusal still reaches the application as `malformed`, on the event and in the
 * profiler; only the log line is missing.
 *
 * @internal
 */
final class CustomTokenVerifier implements TokenVerifierInterface
{
    public function __construct(private readonly Validator $validator) {}

    public function parse(string $compact): ClaimsSet
    {
        return $this->validator->validate(JwtParser::parse($compact));
    }
}
