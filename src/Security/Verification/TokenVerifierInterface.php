<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Verification;

use Medzuch\Jwt\Jwt\ClaimsSet;

/**
 * What a consumer does to a compact token: everything, or throw.
 *
 * The seam exists because a consumer is built two ways. A standardised posture
 * — RFC 9068 above all — comes from one of the library's profile factories,
 * which returns a `ProfileConsumer`; a posture this application defined comes
 * from `ValidatorBuilder`, which returns a `Validator` and no consumer at all.
 * The library's consumer constructors are `@internal` and its `parse()` is
 * `final`, so the second cannot be dressed as the first, and this bundle would
 * be reaching into somebody else's private API to pretend otherwise.
 *
 * One method, and the one the handler was already calling. What it throws is
 * unchanged either way: {@see \Medzuch\Jwt\Exception\JwtException} and its
 * leaves, which {@see \Medzuch\JwtBundle\Security\RejectionReason::of()} maps
 * without knowing which side produced them.
 *
 * @internal
 */
interface TokenVerifierInterface
{
    /**
     * @throws \Medzuch\Jwt\Exception\JwtException on any structural, crypto or claim failure
     */
    public function parse(string $compact): ClaimsSet;
}
