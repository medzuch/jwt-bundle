<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Http;

/**
 * Values going into a `WWW-Authenticate` quoted-string.
 *
 * The bundle refuses a `realm` carrying a quote at container build, so this is
 * the second line rather than the first — but a scope comes from an access
 * rule's attribute, which is a name the application writes and the bundle never
 * sees until a request is denied. A `"` in either would otherwise close the
 * quoted-string and let whatever follows read as further auth-params
 * (RFC 9110 §5.6.4).
 *
 * @internal
 */
final class Challenge
{
    public static function quote(string $value): string
    {
        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
