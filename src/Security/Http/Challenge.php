<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Http;

/**
 * Values going into a `WWW-Authenticate` quoted-string.
 *
 * The bundle refuses a `realm` carrying a quote, a backslash or a control
 * character at container build, so for that half this is the second line rather
 * than the first — but a scope comes from an access rule's attribute, which is
 * a name the application writes and the bundle never sees until a request is
 * denied, so for that half there is no first line. A `"` would close the
 * quoted-string and let whatever follows read as further auth-params, and a
 * control character has no place in one at all (RFC 9110 §5.6.4).
 *
 * @internal
 */
final class Challenge
{
    public static function quote(string $value): string
    {
        // Stripped, not escaped: a quoted-string has no escape for a control
        // character (RFC 9110 §5.6.4), and a newline in a header value is worse
        // than a wrong one — PHP refuses to emit it, so the response goes out
        // with no challenge at all, which is the one thing an entry point
        // exists to prevent.
        $value = (string) preg_replace('/[\x00-\x1F\x7F]/', '', $value);

        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
