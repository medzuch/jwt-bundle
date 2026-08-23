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
    /** What a quoted-string cannot carry at all (RFC 9110 §5.6.4), named here so the config node can refuse it by the same rule. */
    public const CONTROL = '/[\x00-\x1F\x7F]/';

    public static function quote(string $value): string
    {
        // Stripped, not escaped: a quoted-string has no escape for a control
        // character (RFC 9110 §5.6.4), and a newline in a header value is worse
        // than a wrong one — PHP refuses to emit it, so the response goes out
        // with no challenge at all, which is the one thing an entry point
        // exists to prevent.
        // ?? $value rather than a cast: a PCRE failure would otherwise turn
        // into an empty realm, which is a header saying something false rather
        // than one saying too much.
        $value = preg_replace(self::CONTROL, '', $value) ?? $value;

        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
