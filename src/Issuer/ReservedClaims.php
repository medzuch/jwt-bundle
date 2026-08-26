<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use LogicException;

/**
 * The claim names an issuance hook cannot write.
 *
 * The library already refuses the registered ones (RFC 7519 §4.1) in
 * `withClaim()`, but deep inside a builder, where the message cannot say which
 * provider sent it. `client_id` and `scope` it does not refuse at all — ordinary
 * claims to a JWT library, RFC 9068 §2.2 meaning to everyone else.
 *
 * This list is deliberately longer than the one `issuers.*.claims` is checked
 * against at container build, which lets `client_id` and `scope` through:
 * static claims and the arguments of `issue()` are places where someone decided
 * about a token they were looking at. A provider or a listener was not.
 *
 * @internal
 */
final class ReservedClaims
{
    /**
     * RFC 7519 §4.1. The library routes these through typed setters and refuses
     * them in `withClaim()`, whoever sends them.
     *
     * @var list<string>
     */
    public const REGISTERED = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    /**
     * Ordinary claims to a JWT library, RFC 9068 §2.2 meaning to everyone else.
     * Configuration and the arguments of `issue()` may set them deliberately;
     * an ambient hook may not.
     *
     * @var list<string>
     */
    public const OWN = ['client_id', 'scope'];

    /** @var list<string> */
    public const NAMES = [...self::REGISTERED, ...self::OWN];

    /**
     * @param list<string> $names claim names the hook wants to write
     * @param string       $verb  what it was trying to do, so the sentence
     *                            describes the line the stack trace points at
     */
    public static function refuse(array $names, string $origin, string $verb = 'set'): void
    {
        $reserved = array_values(array_intersect($names, self::NAMES));

        if ([] === $reserved) {
            return;
        }

        throw new LogicException(sprintf(
            '%s cannot %s the reserved claim %s. The issuer sets these itself, from its configuration and the arguments of issue(): %s.',
            $origin,
            $verb,
            '"' . implode('", "', $reserved) . '"',
            '"' . implode('", "', self::NAMES) . '"',
        ));
    }
}
