<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Verification;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Profile\ProfileConsumer;

/**
 * A consumer the library builds: RFC 9068, and whatever profiles follow it.
 *
 * A pass-through, which is the point — the profile already is the posture, and
 * the only thing missing was a type the handler could share with the other
 * kind. Everything the profile does beyond validating claims stays where it is:
 * its own `assertProfile()` rules, and its logging of the whole parse under the
 * profile's name.
 *
 * @internal
 */
final class ProfileTokenVerifier implements TokenVerifierInterface
{
    public function __construct(private readonly ProfileConsumer $consumer) {}

    public function parse(string $compact): ClaimsSet
    {
        return $this->consumer->parse($compact);
    }
}
