<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Verification;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\Validator;

/**
 * A consumer for a `typ` this application defined, assembled from the library's
 * lower-level API rather than from a profile.
 *
 * `04-api-surface.md` calls that API "for multi-tenant or custom flows" and
 * freezes it, so this is the documented way to verify a token whose posture is
 * nobody's standard. The three profiles are the standardised postures and there
 * is deliberately no fourth: a token type only this application knows has no
 * posture to standardise.
 *
 * **What differs from a profile consumer.** The `Validator` carries the logger,
 * so claim and crypto outcomes are logged by the library exactly as they are on
 * the other path. What is not logged is a token too malformed to parse at all —
 * that happens before the validator sees it, and the profile's own `parse()` is
 * where the equivalent logging lives. The refusal still reaches the application
 * as `malformed`, on the event and in the profiler; it is the log line that is
 * missing, and reproducing it would mean reimplementing a redaction policy that
 * belongs upstream.
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
