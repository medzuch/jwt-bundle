<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Key;

use Medzuch\Jwt\Exception\InvalidKeyException;
use Medzuch\Jwt\Key\EcPrivateKey;
use Medzuch\Jwt\Key\EcPublicKey;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OkpPrivateKey;
use Medzuch\Jwt\Key\OkpPublicKey;
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
 * A `pem_*` or `jwk_*` value is either the document itself or a path to it,
 * told apart by its first characters — a filesystem path begins with neither
 * `-----BEGIN` nor `{`. Both spellings are normal: a path for a mounted key
 * file, the contents for a key delivered through the environment.
 *
 * A JWK states its own `alg`, `kid` and `use`, and so does the configuration
 * that points at it. The two must agree: the configuration is what the bundle
 * reasons about at build time — which algorithms a consumer can verify, which
 * keys a token can tell apart (DEC-5) — and a document that quietly said
 * something else would make that reasoning describe a different key than the
 * one in use. What the configuration states and the document omits is filled
 * in; a disagreement is refused, naming both readings.
 *
 * @internal
 */
final class KeyLoader
{
    /**
     * Longest value {@see nameSource()} will quote back. Comfortably above any
     * real path and comfortably below any key document.
     */
    private const LONGEST_PRINTABLE_PATH = 255;

    /**
     * The concrete class each half resolves to, so the container can declare
     * what a key service actually is. `PrivateKey` and `PublicKey` are
     * interfaces: naming one as a service class tells `debug:container` and
     * every type check something that can never be true.
     *
     * @return class-string
     */
    public static function signingKeyClass(string $algorithm): string
    {
        return match (SigningAlgorithms::familyOf($algorithm)) {
            SigningAlgorithms::FAMILY_RSA => RsaPrivateKey::class,
            SigningAlgorithms::FAMILY_EC => EcPrivateKey::class,
            SigningAlgorithms::FAMILY_OKP => OkpPrivateKey::class,
            default => throw new InvalidKeyException(sprintf('Algorithm "%s" takes a shared secret, not a key pair.', $algorithm)),
        };
    }

    /**
     * @return class-string
     */
    public static function verificationKeyClass(string $algorithm): string
    {
        return match (SigningAlgorithms::familyOf($algorithm)) {
            SigningAlgorithms::FAMILY_RSA => RsaPublicKey::class,
            SigningAlgorithms::FAMILY_EC => EcPublicKey::class,
            SigningAlgorithms::FAMILY_OKP => OkpPublicKey::class,
            default => throw new InvalidKeyException(sprintf('Algorithm "%s" takes a shared secret, not a key pair.', $algorithm)),
        };
    }

    public static function signingKey(string $source, string $algorithm, ?string $kid, ?string $passphrase): PrivateKey
    {
        $pem = self::read($source, $algorithm, 'PEM', '-----BEGIN');

        return match (SigningAlgorithms::familyOf($algorithm)) {
            SigningAlgorithms::FAMILY_RSA => RsaPrivateKey::fromPem($pem, $algorithm, $kid, null, null, $passphrase),
            SigningAlgorithms::FAMILY_EC => EcPrivateKey::fromPem($pem, $algorithm, $kid, null, null, $passphrase),
            default => throw new InvalidKeyException(sprintf('No PEM key source for algorithm "%s".', $algorithm)),
        };
    }

    public static function verificationKey(string $source, string $algorithm, ?string $kid): PublicKey
    {
        $pem = self::read($source, $algorithm, 'PEM', '-----BEGIN');

        return match (SigningAlgorithms::familyOf($algorithm)) {
            // `use: sig` is stated rather than left out: these keys exist only
            // to verify signatures, some relying parties filter on it before
            // they read `alg`, and it is information the bundle has and the
            // published document would otherwise omit (RFC 7517 §4.2).
            SigningAlgorithms::FAMILY_RSA => RsaPublicKey::fromPem($pem, $algorithm, $kid, KeyUse::Sig),
            SigningAlgorithms::FAMILY_EC => EcPublicKey::fromPem($pem, $algorithm, $kid, KeyUse::Sig),
            default => throw new InvalidKeyException(sprintf('No PEM key source for algorithm "%s".', $algorithm)),
        };
    }

    public static function signingKeyFromJwk(string $source, string $algorithm, ?string $kid): PrivateKey
    {
        $jwk = self::jwk($source, $algorithm, $kid, private: true);

        return match (SigningAlgorithms::familyOf($algorithm)) {
            SigningAlgorithms::FAMILY_RSA => RsaPrivateKey::fromJwk($jwk),
            SigningAlgorithms::FAMILY_EC => EcPrivateKey::fromJwk($jwk),
            SigningAlgorithms::FAMILY_OKP => OkpPrivateKey::fromJwk($jwk),
            default => throw new InvalidKeyException(sprintf('No JWK key source for algorithm "%s".', $algorithm)),
        };
    }

    public static function verificationKeyFromJwk(string $source, string $algorithm, ?string $kid): PublicKey
    {
        $jwk = self::jwk($source, $algorithm, $kid, private: false);

        return match (SigningAlgorithms::familyOf($algorithm)) {
            SigningAlgorithms::FAMILY_RSA => RsaPublicKey::fromJwk($jwk),
            SigningAlgorithms::FAMILY_EC => EcPublicKey::fromJwk($jwk),
            SigningAlgorithms::FAMILY_OKP => OkpPublicKey::fromJwk($jwk),
            default => throw new InvalidKeyException(sprintf('No JWK key source for algorithm "%s".', $algorithm)),
        };
    }

    /**
     * @return array<string, mixed>
     */
    private static function jwk(string $source, string $algorithm, ?string $kid, bool $private): array
    {
        ['content' => $content, 'origin' => $origin] = self::document($source, $algorithm, 'JWK', '{');

        try {
            $decoded = json_decode($content, true, flags: \JSON_THROW_ON_ERROR);
        } catch (\JsonException $invalid) {
            // The reason and the offset are the whole of what the reader needs
            // here, and they are the one part of the document safe to print.
            throw new InvalidKeyException(sprintf('The %s is not valid JSON: %s', $origin, $invalid->getMessage()), 0, $invalid);
        }

        if (!is_array($decoded) || array_is_list($decoded)) {
            throw new InvalidKeyException(sprintf('The %s is not a JSON object.', $origin));
        }

        // A JSON member whose name reads as an integer arrives as an int key.
        $jwk = array_combine(array_map(strval(...), array_keys($decoded)), $decoded);

        // A JWK Set is an object too, and it is the document people have on
        // hand: it is what a JWKS endpoint serves. It has no "kty" because it
        // is not a key, and every check below would read it as a malformed one.
        if (!array_key_exists('kty', $jwk) && array_key_exists('keys', $jwk)) {
            throw new InvalidKeyException(sprintf('The %s is a JWK Set (RFC 7517 §5), not a key source; name one key from it. Consuming a whole set is what a remote JWKS does, and this is not it.', $origin));
        }

        self::assertHalf($jwk, $origin, $private);
        self::assertAgrees($jwk, $origin, 'alg', $algorithm);
        self::assertAgrees($jwk, $origin, 'kid', $kid);

        $jwk['alg'] = $algorithm;

        if (null !== $kid) {
            $jwk['kid'] = $kid;
        }

        self::assertSignatureUse($jwk, $origin);

        if (!$private) {
            // Stated only on the half that gets published: `use` is what a
            // relying party filters on, and the private half is read by this
            // application alone (RFC 7517 §4.2).
            $jwk['use'] = KeyUse::Sig->value;
        }

        return $jwk;
    }

    /**
     * The `d` parameter is what separates the two halves of an asymmetric JWK
     * (RFC 7517 §§8.1, 9.3), and reading it the wrong way round is the mistake
     * with consequences: a private document behind `jwk_public` is published
     * verbatim by the JWKS endpoint, in a document that parses perfectly and
     * returns 200.
     *
     * @param array<string, mixed> $jwk
     */
    private static function assertHalf(array $jwk, string $origin, bool $private): void
    {
        if ($private === array_key_exists('d', $jwk)) {
            return;
        }

        throw new InvalidKeyException($private
            ? sprintf('The %s has no "d": it is a public key, and a signing key needs the private half.', $origin)
            : sprintf('The %s has a "d": it is a private key, and publishing it would give away the key that signs. Point "jwk_public" at the public half.', $origin));
    }

    /**
     * Both halves are signature keys: every key this bundle configures exists
     * to sign or to verify a signature, so a document claiming the other
     * purpose is a different key than the one being described — on the private
     * side too, where it would otherwise sign happily and only be caught, if at
     * all, deep in the library.
     *
     * @param array<string, mixed> $jwk
     */
    private static function assertSignatureUse(array $jwk, string $origin): void
    {
        $use = $jwk['use'] ?? null;

        if (null === $use || KeyUse::Sig->value === $use) {
            return;
        }

        throw new InvalidKeyException(sprintf(
            'The %s is marked use "%s", so it is not a signature key.',
            $origin,
            is_string($use) ? $use : get_debug_type($use),
        ));
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function assertAgrees(array $jwk, string $origin, string $parameter, ?string $configured): void
    {
        $stated = $jwk[$parameter] ?? null;

        if (null === $stated || $stated === $configured) {
            return;
        }

        throw new InvalidKeyException(sprintf(
            'The %s states %s "%s" while the configuration says %s. Change one of them: the configuration is what the container is built from, and the document is what signs.',
            $origin,
            $parameter,
            is_string($stated) ? $stated : get_debug_type($stated),
            null === $configured ? 'nothing' : sprintf('"%s"', $configured),
        ));
    }

    private static function read(string $source, string $algorithm, string $format, string $opening): string
    {
        return self::document($source, $algorithm, $format, $opening)['content'];
    }

    /**
     * The document and how to name it in an error, decided together: inline or
     * a path is one question, and answering it in two places is how an error
     * ends up naming an inline document the loader read from a file.
     *
     * A path is safe to print; the contents of an inline key are not, and a
     * value that turned out to be neither is described rather than quoted
     * ({@see nameSource()}).
     *
     * @return array{content: string, origin: string}
     */
    private static function document(string $source, string $algorithm, string $format, string $opening): array
    {
        if (str_starts_with(ltrim($source), $opening)) {
            return ['content' => $source, 'origin' => sprintf('inline %s %s', $algorithm, $format)];
        }

        $contents = @file_get_contents($source);

        if (false === $contents) {
            // Names both readings, because a value that is neither armoured nor
            // a readable path is as likely to be a mangled inline document as a
            // wrong filename.
            throw new InvalidKeyException(sprintf(
                'Cannot read the %s key from %s: it is neither a readable file nor a %s (which begins with %s).',
                $algorithm,
                self::nameSource($source),
                $format,
                $opening,
            ));
        }

        return ['content' => $contents, 'origin' => sprintf('%s %s in "%s"', $algorithm, $format, $source)];
    }

    /**
     * A value that turned out to be neither armoured nor readable, named for
     * an error message.
     *
     * A filename is the whole of what the reader has to fix, so it is printed.
     * A value that cannot be one — too long, more than a line, or carrying the
     * shape of a key — is far likelier to be a document whose armour was
     * mangled on its way through the environment, and printing that would put
     * key material into a log, an error page and the profiler, which is the one
     * place it must never reach (K9). Those are described instead of quoted.
     *
     * The rule cannot be exact: a short single-line value is printed, because
     * at that length it is a path or nothing usable. Every spelling of a PEM or
     * a JWK is longer than that, or has newlines, or says so.
     */
    private static function nameSource(string $source): string
    {
        $printable = !str_contains($source, "\n")
            && !str_contains($source, "\r")
            && strlen($source) <= self::LONGEST_PRINTABLE_PATH
            && !str_contains($source, '-----')
            && !str_contains($source, '"d"');

        return $printable
            ? sprintf('"%s"', $source)
            : sprintf(
                'a %d-byte value spanning %d lines, not printed in case it is key material',
                strlen($source),
                substr_count($source, "\n") + 1,
            );
    }
}
