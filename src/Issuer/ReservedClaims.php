<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use LogicException;

/**
 * The claim names an issuance hook cannot write.
 *
 * The registered ones (RFC 7519 §4.1) the library already refuses through
 * `withClaim()`, but it refuses them deep inside a builder, where the message
 * cannot say which of an application's providers sent it. `client_id` and
 * `scope` it does not refuse at all — ordinary claims to a JWT library, RFC
 * 9068 §2.2 meaning to everyone else — so a provider returning `scope` would
 * silently replace what the caller asked to grant.
 *
 * This list is longer than the one configuration is checked against at
 * container build: `issuers.*.claims` refuses the registered names only, and
 * lets `client_id` and `scope` through deliberately — static claims and the
 * arguments of `issue()` are both places where someone decided about a token
 * they were looking at. A provider or a listener was not looking at it, which
 * is the whole reason this list is stricter.
 *
 * @internal
 */
final class ReservedClaims
{
    /** @var list<string> */
    public const NAMES = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'client_id', 'scope'];

    /**
     * @param list<string> $names claim names the hook wants to write
     */
    public static function refuse(array $names, string $origin): void
    {
        $reserved = array_values(array_intersect($names, self::NAMES));

        if ([] === $reserved) {
            return;
        }

        throw new LogicException(sprintf(
            '%s cannot set the reserved claim %s. The issuer sets these itself, from its configuration and the arguments of issue(): %s.',
            $origin,
            '"' . implode('", "', $reserved) . '"',
            '"' . implode('", "', self::NAMES) . '"',
        ));
    }
}
