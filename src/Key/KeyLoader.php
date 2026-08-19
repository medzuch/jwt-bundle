<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Key\PublicKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Key\RsaPublicKey;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;

/**
 * Turns what configuration can name into a library key.
 *
 * Called from the container as a service factory, never at build time: a key
 * read while compiling would be baked into the compiled container, where a
 * private key has no business being (K9).
 *
 * A `pem_*` value is either the PEM itself or a path to it, told apart by the
 * armour — a filesystem path cannot begin with `-----BEGIN`. Both spellings are
 * normal: a path for a mounted key file, the contents for a key delivered
 * through the environment.
 *
 * @internal
 */
final class KeyLoader
{
    public static function signingKey(string $source, string $algorithm, ?string $kid, ?string $passphrase): PrivateKey
    {
        $pem = self::read($source, $algorithm);

        return match (SigningAlgorithms::familyOf($algorithm)) {
            SigningAlgorithms::FAMILY_RSA => RsaPrivateKey::fromPem($pem, $algorithm, $kid, null, null, $passphrase),
            SigningAlgorithms::FAMILY_EC => EcPrivateKey::fromPem($pem, $algorithm, $kid, null, null, $passphrase),
            default => throw new InvalidKeyException(sprintf('No PEM key source for algorithm "%s".', $algorithm)),
        };
    }

    public static function verificationKey(string $source, string $algorithm, ?string $kid): PublicKey
    {
        $pem = self::read($source, $algorithm);

        return match (SigningAlgorithms::familyOf($algorithm)) {
            SigningAlgorithms::FAMILY_RSA => RsaPublicKey::fromPem($pem, $algorithm, $kid),
            SigningAlgorithms::FAMILY_EC => EcPublicKey::fromPem($pem, $algorithm, $kid),
            default => throw new InvalidKeyException(sprintf('No PEM key source for algorithm "%s".', $algorithm)),
        };
    }

    private static function read(string $source, string $algorithm): string
    {
        if (str_starts_with(ltrim($source), '-----BEGIN')) {
            return $source;
        }

        $pem = @file_get_contents($source);

        if (false === $pem) {
            // The path, not the contents: naming a file that could not be read
            // is the whole diagnostic, and nothing secret is in the path.
            throw new InvalidKeyException(sprintf('Cannot read the %s key file "%s".', $algorithm, $source));
        }

        return $pem;
    }
}
