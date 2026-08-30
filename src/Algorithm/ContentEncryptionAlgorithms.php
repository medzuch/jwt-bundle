<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Algorithm;

use Medzuch\Jwt\Algorithm\Encryption\A128CbcHs256;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A192CbcHs384;
use Medzuch\Jwt\Algorithm\Encryption\A192Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A256CbcHs512;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;

/**
 * JWE `enc` names the bundle accepts in configuration, and the library class
 * implementing each: how the claims themselves are encrypted, once the two
 * sides hold the same Content Encryption Key (RFC 7518 §5).
 *
 * All six the RFC registers as Required or Recommended, and no others. Every
 * one is authenticated encryption, so this list has nothing in it of the kind
 * an allowlist normally exists to keep out — but it is still configured rather
 * than assumed, because the header of an arriving token must never be what
 * decides how that token is read (RFC 8725 §3.1).
 *
 * @internal
 */
final class ContentEncryptionAlgorithms
{
    /** @var array<string, class-string> */
    public const CLASSES = [
        'A128GCM' => A128Gcm::class,
        'A192GCM' => A192Gcm::class,
        'A256GCM' => A256Gcm::class,
        'A128CBC-HS256' => A128CbcHs256::class,
        'A192CBC-HS384' => A192CbcHs384::class,
        'A256CBC-HS512' => A256CbcHs512::class,
    ];

    /** @return list<string> */
    public static function names(): array
    {
        return array_keys(self::CLASSES);
    }
}
