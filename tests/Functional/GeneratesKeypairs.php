<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use RuntimeException;

/**
 * Key material for tests, generated per run rather than committed: a fixture
 * keypair in a repository is a keypair someone eventually uses in anger.
 *
 * Cached per name within a class, because RSA generation is the slowest thing
 * in this suite by an order of magnitude.
 */
trait GeneratesKeypairs
{
    /** @var array<string, array{private: string, public: string}> */
    private static array $keypairs = [];

    /**
     * @param array<string, mixed> $options
     *
     * @return array{private: string, public: string}
     */
    private static function keypair(string $name, array $options = ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]): array
    {
        return self::$keypairs[$name] ??= self::freshKeypair($options);
    }

    /**
     * An Ed25519 pair as the two JWKs RFC 8037 §2 describes, JSON-encoded.
     * There is no PEM to generate from: the JWK is the key's only spelling,
     * which is why it took a JWK source to reach EdDSA at all.
     *
     * @return array{private: string, public: string}
     */
    private static function ed25519Jwks(?string $kid = null): array
    {
        $seed = random_bytes(\SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $public = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));

        $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'alg' => 'EdDSA', 'x' => self::base64Url($public)];

        if (null !== $kid) {
            $jwk['kid'] = $kid;
        }

        return [
            'private' => self::encodeJwk($jwk + ['d' => self::base64Url($seed)]),
            'public' => self::encodeJwk($jwk),
        ];
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function encodeJwk(array $jwk): string
    {
        return json_encode($jwk, \JSON_THROW_ON_ERROR);
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array{private: string, public: string}
     */
    private static function freshKeypair(array $options = ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]): array
    {
        $resource = openssl_pkey_new($options);

        if (false === $resource || !openssl_pkey_export($resource, $private)) {
            throw new RuntimeException('could not generate a keypair');
        }

        $details = openssl_pkey_get_details($resource);

        if (!is_array($details) || !is_string($details['key'])) {
            throw new RuntimeException('could not read the public key');
        }

        return ['private' => (string) $private, 'public' => $details['key']];
    }
}
