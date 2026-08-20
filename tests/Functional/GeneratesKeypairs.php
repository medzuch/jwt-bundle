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
