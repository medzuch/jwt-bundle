<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Algorithm;

use Medzuch\Jwt\Algorithm\Signing\EdDsa;
use Medzuch\Jwt\Algorithm\Signing\Es256;
use Medzuch\Jwt\Algorithm\Signing\Es384;
use Medzuch\Jwt\Algorithm\Signing\Es512;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs384;
use Medzuch\Jwt\Algorithm\Signing\Hs512;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Algorithm\Signing\Rs384;
use Medzuch\Jwt\Algorithm\Signing\Rs512;

/**
 * JOSE `alg` names the bundle accepts in configuration, and the library class
 * implementing each.
 *
 * `none` is absent and always will be: RFC 8725 §3.1 is the reason the library
 * refuses it by construction, and a configuration key that could reintroduce it
 * would undo that.
 *
 * The list is deliberately wider than what can be configured today — only HMAC
 * keys have a source so far. Naming an algorithm with no key behind it fails at
 * container build with a message that says so, which beats an enum that grows
 * with each key source and gives "is not a supported value" for an algorithm
 * the library implements perfectly well.
 *
 * @internal
 */
final class SigningAlgorithms
{
    /** @var array<string, class-string> */
    public const CLASSES = [
        'HS256' => Hs256::class,
        'HS384' => Hs384::class,
        'HS512' => Hs512::class,
        'RS256' => Rs256::class,
        'RS384' => Rs384::class,
        'RS512' => Rs512::class,
        'ES256' => Es256::class,
        'ES384' => Es384::class,
        'ES512' => Es512::class,
        'EdDSA' => EdDsa::class,
    ];

    public const FAMILY_HMAC = 'hmac';
    public const FAMILY_RSA = 'rsa';
    public const FAMILY_EC = 'ec';
    public const FAMILY_OKP = 'okp';

    /**
     * The key family each algorithm needs. A key is bound to one algorithm and
     * a family answers what kind of material that algorithm can be given.
     *
     * @var array<string, string>
     */
    public const FAMILIES = [
        'HS256' => self::FAMILY_HMAC,
        'HS384' => self::FAMILY_HMAC,
        'HS512' => self::FAMILY_HMAC,
        'RS256' => self::FAMILY_RSA,
        'RS384' => self::FAMILY_RSA,
        'RS512' => self::FAMILY_RSA,
        'ES256' => self::FAMILY_EC,
        'ES384' => self::FAMILY_EC,
        'ES512' => self::FAMILY_EC,
        'EdDSA' => self::FAMILY_OKP,
    ];

    /** @var list<string> */
    public const HMAC = ['HS256', 'HS384', 'HS512'];

    /** @return list<string> */
    public static function names(): array
    {
        return array_keys(self::CLASSES);
    }

    public static function familyOf(string $algorithm): string
    {
        return self::FAMILIES[$algorithm] ?? throw new \InvalidArgumentException(sprintf('Unknown algorithm "%s".', $algorithm));
    }

    /** @return list<string> */
    public static function namesForFamily(string $family): array
    {
        return array_keys(array_filter(self::FAMILIES, static fn(string $f): bool => $f === $family));
    }
}
