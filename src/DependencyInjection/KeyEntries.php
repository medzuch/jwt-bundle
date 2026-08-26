<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

/**
 * The `keys:` section normalised, and the two questions asked of an entry.
 *
 * The tree leaves an unused source absent rather than null, so entries are
 * filled out once here and every reader afterwards can index all eight fields.
 * The two predicates sit beside them because both the registration and the
 * build-time refusals ask them.
 *
 * @internal
 */
final class KeyEntries
{
    /**
     * @param array<string, array{hmac?: string, pem_private?: string, pem_public?: string, jwk_private?: string, jwk_public?: string, pem_passphrase?: string, algorithm: string, kid: string|null}> $keys
     *
     * @return array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>
     */
    public static function of(array $keys): array
    {
        $entries = [];

        foreach ($keys as $name => $key) {
            $entries[$name] = [
                'hmac' => $key['hmac'] ?? null,
                'pem_private' => $key['pem_private'] ?? null,
                'pem_public' => $key['pem_public'] ?? null,
                'jwk_private' => $key['jwk_private'] ?? null,
                'jwk_public' => $key['jwk_public'] ?? null,
                'pem_passphrase' => $key['pem_passphrase'] ?? null,
                'algorithm' => $key['algorithm'],
                'kid' => $key['kid'],
            ];
        }

        return $entries;
    }

    /**
     * Which halves a key entry has, whatever the material is spelled as. A
     * shared secret is both halves at once; a PEM or JWK pair is whichever of
     * the two it was given.
     *
     * @param array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null} $key
     */
    public static function hasPrivateHalf(array $key): bool
    {
        return null !== $key['hmac'] || null !== $key['pem_private'] || null !== $key['jwk_private'];
    }

    /**
     * @param array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null} $key
     */
    public static function hasPublicHalf(array $key): bool
    {
        return null !== $key['hmac'] || null !== $key['pem_public'] || null !== $key['jwk_public'];
    }
}
