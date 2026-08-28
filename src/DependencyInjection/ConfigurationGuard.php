<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

use Medzuch\Jwt\Jwt\MediaType;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Medzuch\JwtBundle\Security\User\JwtUserFactoryInterface;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The refusals that take more than one configuration node to decide.
 *
 * A node validates itself wherever the answer is inside it — an enum, a range,
 * a string that may not be empty. What lives here needs a second node to look
 * at: whether a consumer can verify anything with the keys it names, whether
 * two keys in one set can be told apart, whether a `token_type` collides with
 * a profile the library already has. All of it throws while the container is
 * built, because a security posture that is wrong is better as a failed deploy
 * than as a running application.
 *
 * @internal
 */
final class ConfigurationGuard
{
    /**
     * Claims a custom consumer requires unless it says otherwise.
     *
     * `exp` and nothing else. The library checks `exp`, `nbf` and `iat` only
     * where the token carries them, so a custom posture that required nothing
     * would accept a credential with no expiry at all — one that lives until
     * somebody rotates a key. The profiles all require more than this; they can,
     * because they know what their tokens are for.
     */
    public const DEFAULT_REQUIRED_CLAIMS = ['exp'];

    /**
     * Types the library has a profile for, which `token_type` must not name:
     * a consumer wanting one of these postures gets it by leaving the key out.
     */
    private const PROFILE_TOKEN_TYPES = [
        'at+jwt' => 'the RFC 9068 access-token profile, which a consumer uses by default',
        'JWT' => 'the generic RFC 7519 type',
    ];

    /**
     * The same name twice is always a mistake and never a rotation: it puts one
     * key in a set twice, which no resolver anywhere benefits from.
     *
     * @param list<string> $names
     */
    public static function assertNamesAreUnique(string $context, array $names): void
    {
        $duplicates = array_keys(array_filter(array_count_values($names), static fn(int $count): bool => $count > 1));

        if ([] !== $duplicates) {
            throw new InvalidConfigurationException(sprintf(
                '%s names key "%s" more than once.',
                $context,
                implode('", "', $duplicates),
            ));
        }
    }

    /**
     * Two keys a token cannot tell apart — sharing a `kid`, or sharing an
     * algorithm with no `kid` at all — mean the second verifies nothing and
     * rotation silently invalidates every token in flight. DEC-5 has why
     * resolution is first-match-wins in both directions and never falls back.
     *
     * The ambiguity is a property of one verification set rather than of the
     * configuration as a whole, and that is what makes checking per-consumer
     * mandatory: the resolver only ever sees the keys of the consumer doing the
     * verifying, and a global check would reject the most ordinary asymmetric
     * setup there is — a private entry and a public entry that carry the same
     * `kid` precisely because they are the same key.
     *
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
     */
    public static function assertKeysAreDistinguishable(string $context, array $keys): void
    {
        $anonymousByAlgorithm = [];
        $namesByKid = [];

        foreach ($keys as $name => $key) {
            if (null === $key['kid']) {
                $anonymousByAlgorithm[$key['algorithm']][] = $name;

                continue;
            }

            $namesByKid[$key['kid']][] = $name;
        }

        foreach ($anonymousByAlgorithm as $algorithm => $names) {
            if (count($names) > 1) {
                throw new InvalidConfigurationException(sprintf(
                    '%s uses keys "%s", all bound to %s with no "kid", so a token cannot say which one signed it. Give each of them a kid.',
                    $context,
                    implode('", "', $names),
                    $algorithm,
                ));
            }
        }

        foreach ($namesByKid as $kid => $names) {
            if (count($names) > 1) {
                throw new InvalidConfigurationException(sprintf(
                    '%s uses keys "%s", which share the kid "%s". Selection by kid reaches the first of them and never the others.',
                    $context,
                    implode('", "', $names),
                    $kid,
                ));
            }
        }
    }

    /**
     * A named key exists and has the private half signing needs.
     *
     * Shared by access-token issuers and security-event streams because the
     * question is the same one, and a second copy would be a second chance for
     * the two to answer it differently. `$context` carries the noun so the
     * message names what the reader wrote — an issuer, or a stream.
     *
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
     */
    public static function assertCanSign(string $context, string $key, array $keys): void
    {
        if (!isset($keys[$key])) {
            throw new InvalidConfigurationException(sprintf(
                '%s signs with key "%s", which is not defined under medzuch_jwt.keys. Defined: %s.',
                $context,
                $key,
                [] === $keys ? 'none' : '"' . implode('", "', array_keys($keys)) . '"',
            ));
        }

        if (!KeyEntries::hasPrivateHalf($keys[$key])) {
            throw new InvalidConfigurationException(sprintf(
                '%s signs with key "%s", which has only a public half. Signing needs the private half.',
                $context,
                $key,
            ));
        }
    }

    /**
     * @param array{uri: string|null, discovery: string|null, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int} $set
     */
    public static function assertRemoteJwksIsUsable(string $name, array $set, ContainerBuilder $builder): void
    {
        if (null !== $set['cache'] && null !== $set['cache_pool']) {
            throw new InvalidConfigurationException(sprintf('Remote JWK Set "%s" names both a PSR-16 cache and a PSR-6 pool. Give one: "cache" is used as it is, "cache_pool" is wrapped.', $name));
        }

        if (null !== $set['uri'] && null !== $set['discovery']) {
            throw new InvalidConfigurationException(sprintf('Remote JWK Set "%s" names both a jwks_uri and a discovery issuer. Give one: "uri" is fetched as it is, "discovery" reads it from the issuer\'s metadata.', $name));
        }

        if (null === $set['uri'] && null === $set['discovery']) {
            throw new InvalidConfigurationException(sprintf('Remote JWK Set "%s" names neither a jwks_uri nor a discovery issuer. Give "uri" for a fixed endpoint, or "discovery" for the issuer identifier to read it from.', $name));
        }

        // The same test the library makes, in the same direction: everything
        // that is not https is refused, rather than the one spelling of
        // plaintext that comes to mind. "HTTP://", "ftp://" and a bare host are
        // all not-https, and a check that named only "http://" would let each
        // of them reach the first token before failing.
        //
        // Both spellings are held to it. A `jwks_uri` read from a discovery
        // document is checked again when it arrives, because that one is the
        // issuer's to choose and no configuration can settle it in advance.
        //
        // A value assembled from the environment is exempt because there is
        // nothing to read yet: it is a placeholder until the container is
        // compiled. The resolver's constructor is the fence for that spelling —
        // the library's for a `uri`, this bundle's own for a `discovery` — so
        // an env var holding plaintext fails when the service is first built
        // rather than reaching a token.
        $configured = $set['uri'] ?? $set['discovery'];
        \assert(is_string($configured));

        $builder->resolveEnvPlaceholders($configured, null, $fromEnvironment);

        if ([] === ($fromEnvironment ?? []) && '' === trim($configured)) {
            throw new InvalidConfigurationException(sprintf('Remote JWK Set "%s" has a blank %s; omit it instead.', $name, null !== $set['uri'] ? 'uri' : 'discovery'));
        }

        if ([] === ($fromEnvironment ?? []) && 0 !== stripos($configured, 'https://')) {
            throw new InvalidConfigurationException(null !== $set['uri']
                ? sprintf('Remote JWK Set "%s" has a jwks_uri that is not https. Verification keys taken from a channel an attacker can rewrite are not verification keys (RFC 8725 §3.10). Got "%s".', $name, $configured)
                : sprintf('Remote JWK Set "%s" has a discovery issuer that is not https. An issuer identifier fetched over a channel an attacker can rewrite names whatever keys they like (RFC 8725 §3.10). Got "%s".', $name, $configured));
        }

        if (null === $set['cache'] && !class_exists(Psr16Cache::class)) {
            throw new InvalidConfigurationException(sprintf('Remote JWK Set "%s" wraps a PSR-6 pool with %s, which is not installed. Run "composer require symfony/cache", or name a PSR-16 service under "cache".', $name, Psr16Cache::class));
        }
    }

    /**
     * A key entry names exactly one kind of material, and the algorithm decides
     * which kind it must be — an RSA algorithm cannot be given a shared secret,
     * and HS256 cannot be given a PEM. Both would fail when the key is first
     * built, deep in the library, describing the material rather than the
     * configuration that chose it.
     *
     * @param array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null} $key
     */
    public static function assertKeyMaterialMatchesAlgorithm(string $name, array $key): void
    {
        $family = SigningAlgorithms::familyOf($key['algorithm']);
        $hasPem = null !== $key['pem_private'] || null !== $key['pem_public'];
        $hasJwk = null !== $key['jwk_private'] || null !== $key['jwk_public'];
        $kinds = (int) (null !== $key['hmac']) + (int) $hasPem + (int) $hasJwk;

        if ($kinds > 1) {
            throw new InvalidConfigurationException(sprintf('Key "%s" gives more than one kind of material. A key is one thing: a shared secret, a PEM pair or a JWK pair.', $name));
        }

        if (0 === $kinds) {
            throw new InvalidConfigurationException(sprintf('Key "%s" has no material: give it "hmac", or the private and/or public half as "pem_*" or "jwk_*".', $name));
        }

        if (SigningAlgorithms::FAMILY_HMAC === $family && null === $key['hmac']) {
            throw new InvalidConfigurationException(sprintf('Key "%s" is bound to %s, which takes a shared secret, not a key pair. Set "algorithm" to an RSA, EC or OKP one.', $name, $key['algorithm']));
        }

        if (SigningAlgorithms::FAMILY_HMAC !== $family && null !== $key['hmac']) {
            throw new InvalidConfigurationException(sprintf('Key "%s" is bound to %s, which needs a key pair, not a shared secret. The shared-secret algorithms are %s.', $name, $key['algorithm'], implode('/', SigningAlgorithms::namesForFamily(SigningAlgorithms::FAMILY_HMAC))));
        }

        // Ed25519 has no standard PEM spelling the library reads: RFC 8037
        // defines the key as a JWK, and that is the only source for it.
        if (SigningAlgorithms::FAMILY_OKP === $family && $hasPem) {
            throw new InvalidConfigurationException(sprintf('Key "%s" is bound to %s, which is configured as a JWK: use "jwk_private" and/or "jwk_public".', $name, $key['algorithm']));
        }

        if (null !== $key['pem_passphrase'] && null === $key['pem_private']) {
            throw new InvalidConfigurationException(sprintf('Key "%s" has a passphrase but no "pem_private" to unlock. A JWK carries no passphrase; keep it in a file the application can read and nobody else.', $name));
        }
    }

    /**
     * Each mode answers the question a different way, so an option belonging to
     * one of the others is not a harmless extra: it is a statement about the
     * user that nothing will read.
     *
     * @param array{mode: string, identity_claim: string, factory: string|null, roles: array{claim: string|null, separator: string|null, prefix: string, defaults: list<string>}} $user
     */
    public static function assertUserModeIsCoherent(string $name, array $user): void
    {
        if ('custom' === $user['mode'] && null === $user['factory']) {
            throw new InvalidConfigurationException(sprintf('Consumer "%s" uses user mode "custom" but names no "factory". Give the service id of a %s.', $name, JwtUserFactoryInterface::class));
        }

        if ('custom' !== $user['mode'] && null !== $user['factory']) {
            throw new InvalidConfigurationException(sprintf('Consumer "%s" names a user "factory" but its mode is "%s", which never calls one. Set mode to "custom", or drop the factory.', $name, $user['mode']));
        }

        if ('claims' === $user['mode']) {
            return;
        }

        if (null !== $user['roles']['claim'] || [] !== $user['roles']['defaults']) {
            throw new InvalidConfigurationException(sprintf(
                'Consumer "%s" maps roles from claims but its mode is "%s", where roles come from %s. Set mode to "claims", or drop the "roles" section.',
                $name,
                $user['mode'],
                'provider' === $user['mode'] ? 'the user provider' : 'your factory',
            ));
        }
    }

    /**
     * @param array{service: string|null, cache_pool: string|null, cache: string|null, prefix: string} $denylist
     */
    private static function hasDenylist(array $denylist): bool
    {
        return null !== $denylist['service'] || null !== $denylist['cache_pool'] || null !== $denylist['cache'];
    }

    /**
     * The ways a `token_type` and what it implies can disagree.
     *
     * @param array{token_type: string|null, required_claims: list<mixed>, max_token_age: int|null, denylist: array{service: string|null, cache_pool: string|null, cache: string|null, prefix: string}, ...} $consumer
     */
    public static function assertTokenTypeIsUsable(string $name, array $consumer): void
    {
        if (null === $consumer['token_type']) {
            // A list of required claims with no type to require them for is a
            // setting nothing will read: the RFC 9068 profile brings its own,
            // and they are not this bundle's to widen. Emptiness is how the
            // tree spells "not written" — Symfony 6.4 refuses a null default on
            // an array node — which is the same reading `roles.defaults` takes.
            if ([] !== $consumer['required_claims']) {
                throw new InvalidConfigurationException(sprintf('Consumer "%s" lists "required_claims" without a "token_type". The RFC 9068 profile decides its own required claims; the list is read only for a token type you define.', $name));
            }

            return;
        }

        // RFC 7515 §4.1.9 puts the bare form on the wire, so a configured value
        // carrying the prefix would match nothing a peer ever sends. The library
        // refuses it too, when the validator is built — which is the first
        // request rather than the deploy.
        if (0 === stripos($consumer['token_type'], 'application/')) {
            throw new InvalidConfigurationException(sprintf('Consumer "%s" gives a "token_type" of "%s". RFC 7515 §4.1.9 puts the bare form in the header, so drop the "application/" prefix or no token will ever match it.', $name, $consumer['token_type']));
        }

        if ($consumer['token_type'] !== trim($consumer['token_type'])) {
            throw new InvalidConfigurationException(sprintf('Consumer "%s" gives a "token_type" padded with whitespace ("%s"). A `typ` header is compared as it arrives, so the padding would match nothing a peer sends.', $name, $consumer['token_type']));
        }

        // A type the library already has a profile for is a type this bundle
        // already verifies properly. Naming it here builds a bare validator
        // instead — the same tokens, checked against `required_claims` rather
        // than against the profile's own rules — which reads in YAML as being
        // explicit about RFC 9068 and is the weaker posture of the two.
        foreach (self::PROFILE_TOKEN_TYPES as $reserved => $profile) {
            if (MediaType::equivalent($consumer['token_type'], $reserved)) {
                throw new InvalidConfigurationException(sprintf('Consumer "%s" names "%s" as its "token_type", which is what %s verifies — and this would verify those tokens with fewer rules, not more. Leave "token_type" out for that posture.', $name, $consumer['token_type'], $profile));
            }
        }

        $required = [] === $consumer['required_claims'] ? self::DEFAULT_REQUIRED_CLAIMS : $consumer['required_claims'];

        foreach ($required as $claim) {
            if (!is_string($claim)) {
                throw new InvalidConfigurationException(sprintf('Consumer "%s" lists a "required_claims" entry that is not a claim name (%s). A claim is named by a string.', $name, get_debug_type($claim)));
            }
        }

        // A list of your own replaces the default, `exp` included, and the
        // library checks an expiry only where the token carries one. Dropping
        // it is a real thing to want — a token bounded by its age instead — and
        // a token bounded by nothing at all is not.
        if (!in_array('exp', $required, true) && null === $consumer['max_token_age']) {
            throw new InvalidConfigurationException(sprintf('Consumer "%s" requires claims that do not include "exp" and sets no "max_token_age", so a token it accepts need never stop being valid. Add "exp" to the list, or bound the age instead.', $name));
        }

        // The profiles all require `jti`, so a denylist on one always has
        // something to look up; a type this application defined need not carry
        // one, and the handler refuses a token it cannot name. Unchecked, that
        // is a consumer which compiles, revokes nothing, and refuses every
        // well-formed token as though the token were at fault.
        if (self::hasDenylist($consumer['denylist']) && !in_array('jti', $required, true)) {
            throw new InvalidConfigurationException(sprintf('Consumer "%s" has a denylist and does not require "jti", which is what a denylist looks a token up by. Add "jti" to "required_claims", or drop the denylist.', $name));
        }
    }

    /**
     * @param array{keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, ...}                                                                                                                                                                                              $consumer
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                              $keys
     * @param array<string, array{uri: string|null, discovery: string|null, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>                                                                                                     $sets
     */
    public static function assertCanVerify(string $context, array $consumer, array $keys, array $sets): void
    {
        if ([] === $consumer['keys'] && null === $consumer['remote_jwks']) {
            throw new InvalidConfigurationException(sprintf('%s has nothing to verify with: give it "keys", "remote_jwks", or both.', $context));
        }

        if (null !== $consumer['remote_jwks'] && !isset($sets[$consumer['remote_jwks']])) {
            throw new InvalidConfigurationException(sprintf(
                '%s verifies against remote JWK Set "%s", which is not defined under medzuch_jwt.remote_jwks. Defined: %s.',
                $context,
                $consumer['remote_jwks'],
                [] === $sets ? 'none' : '"' . implode('", "', array_keys($sets)) . '"',
            ));
        }

        $bound = [];

        foreach ($consumer['keys'] as $key) {
            if (!isset($keys[$key])) {
                throw new InvalidConfigurationException(sprintf(
                    '%s names key "%s", which is not defined under medzuch_jwt.keys. Defined: %s.',
                    $context,
                    $key,
                    [] === $keys ? 'none' : '"' . implode('", "', array_keys($keys)) . '"',
                ));
            }

            if (!KeyEntries::hasPublicHalf($keys[$key])) {
                throw new InvalidConfigurationException(sprintf(
                    '%s verifies with key "%s", which has only a private half. Verification needs the public one — a private key cannot stand in for it.',
                    $context,
                    $key,
                ));
            }

            $bound[] = $keys[$key]['algorithm'];
        }

        self::assertNamesAreUnique($context, $consumer['keys']);
        self::assertKeysAreDistinguishable($context, array_intersect_key($keys, array_flip($consumer['keys'])));

        // Every allowed algorithm must have a key behind it, not merely one of
        // them: an algorithm on the allowlist that no key can verify is a
        // permanently dead branch, and the usual way to get one is asking for
        // an algorithm this release has no key source for.
        //
        // The check only holds while every key source is static. A remote set
        // publishes its algorithms at runtime and may rotate to a new one
        // without redeploying this application, so an allowlist entry that no
        // *local* key satisfies is not dead — it is the reason the remote set
        // is there. With one configured, the question this check asks has no
        // build-time answer, so it is not asked.
        $unsatisfied = null === $consumer['remote_jwks'] ? array_values(array_diff($consumer['allowed_algorithms'], $bound)) : [];

        if ([] !== $unsatisfied) {
            throw new InvalidConfigurationException(sprintf(
                '%s allows %s, but none of its keys is bound to %s, so a token using it could never be verified. Its keys are bound to: %s.',
                $context,
                implode('/', $unsatisfied),
                1 === count($unsatisfied) ? 'it' : 'them',
                implode('/', array_unique($bound)),
            ));
        }
    }
}
