<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Algorithm;

use Medzuch\Jwt\Algorithm\KeyManagement\A128GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\A192GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A192Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\A256GcmKw;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\Dir;

/**
 * JWE `alg` names the bundle accepts in configuration, and the library class
 * implementing each. The counterpart of {@see SigningAlgorithms}, for the
 * question a JWE asks that a JWS does not: how the two sides agree on the
 * Content Encryption Key (RFC 7518 §4).
 *
 * Every scheme here takes a shared secret, which is the whole list of them the
 * library ships bar ECDH-ES. RSA key encryption is absent because the library
 * has none (its D-003 defers RSA-OAEP and refuses RSA1_5 outright), and
 * ECDH-ES because encrypting to somebody's public EC key needs a registry of
 * asymmetric encryption keys and a way to publish this application's own —
 * neither of which exists yet, and both of which are a larger thing than an
 * entry in this list.
 *
 * @internal
 */
final class KeyManagementAlgorithms
{
    /**
     * Direct encryption: the configured key *is* the Content Encryption Key,
     * so it is bound to the content-encryption algorithm rather than to this
     * name. Named because three separate rules turn on it.
     */
    public const DIRECT = 'dir';

    /** @var array<string, class-string> */
    public const CLASSES = [
        self::DIRECT => Dir::class,
        'A128KW' => A128Kw::class,
        'A192KW' => A192Kw::class,
        'A256KW' => A256Kw::class,
        'A128GCMKW' => A128GcmKw::class,
        'A192GCMKW' => A192GcmKw::class,
        'A256GCMKW' => A256GcmKw::class,
    ];

    /** @return list<string> */
    public static function names(): array
    {
        return array_keys(self::CLASSES);
    }
}
