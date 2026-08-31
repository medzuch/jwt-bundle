<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

use InvalidArgumentException;
use Medzuch\Jwt\Jwt\MediaType;
use Medzuch\JwtBundle\Algorithm\ContentEncryptionAlgorithms;
use Medzuch\JwtBundle\Algorithm\KeyManagementAlgorithms;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Medzuch\JwtBundle\Oidc\MetadataController;
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
        'secevent+jwt' => 'the RFC 8417 Security Event Token profile, configured under security_events',
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
     * @param array<string, array{algorithm: string, kid: string|null, ...}> $keys
     * @param string                                                          $made what a token would have to say which key it was: the verb belongs
     *                                                                              to the question being asked of the set, and a JWE asks a different one
     */
    public static function assertKeysAreDistinguishable(string $context, array $keys, string $made = 'signed'): void
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
                    '%s uses keys "%s", all bound to %s with no "kid", so a token cannot say which one %s it. Give each of them a kid.',
                    $context,
                    implode('", "', $names),
                    $algorithm,
                    $made,
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
     * The metadata document is worth serving before it is served (K8).
     *
     * Everything here fails at container build rather than at the endpoint,
     * for the reason the JWK Set publisher already has: the one thing a
     * document like this must never do is succeed at the wrong moment. A
     * relying party that reads an issuer identifier it cannot verify against,
     * or a `jwks_uri` over plaintext, has been handed the shape of trust
     * without the substance — and it arrives with a 200.
     *
     * `response_types_supported` is refused when absent because RFC 8414 §2
     * requires it and this bundle cannot supply it: it describes grants an
     * authorization server runs, which is §8's third non-goal. Serving a
     * document without it would publish something that claims conformance and
     * does not have it.
     *
     * @param array{issuer: string|null, jwks_uri: string|null, extra: array<string, mixed>, cache_max_age: int} $metadata
     */
    public static function assertMetadataIsPublishable(array $metadata, ContainerBuilder $builder): void
    {
        foreach (['issuer', 'jwks_uri'] as $member) {
            if (array_key_exists($member, $metadata['extra'])) {
                throw new InvalidConfigurationException(sprintf('medzuch_jwt.metadata.extra names "%s", which is the option above it. Set it there: two spellings of one member could disagree, and the document may only say it once.', $member));
            }
        }

        // The RFC 8414 §2 rules themselves live in MetadataController, which
        // is the one place that implements them: it runs them again when the
        // service is built, where a `%env(...)%` finally has a value. Here they
        // run on what the container can already read, so a literal mistake
        // fails with the configuration key that made it rather than as a
        // service-construction error three layers down.
        $readable = [];

        foreach (['issuer', 'jwks_uri'] as $member) {
            $value = $metadata[$member];

            if (null === $value) {
                continue;
            }

            // Read through the placeholder resolver rather than judged by a
            // tree closure, for the reason `remote_jwks` records: a validate()
            // closure runs against a dummy empty string during
            // ValidateEnvPlaceholdersPass, and would refuse `%env(APP_URL)%`.
            $builder->resolveEnvPlaceholders($value, null, $fromEnvironment);

            if ([] === ($fromEnvironment ?? [])) {
                $readable[$member] = $value;
            }
        }

        try {
            MetadataController::assertPublishable($readable);
        } catch (InvalidArgumentException $e) {
            throw new InvalidConfigurationException(sprintf('medzuch_jwt.metadata is not publishable: %s', $e->getMessage()), previous: $e);
        }

        if (!array_key_exists('response_types_supported', $metadata['extra'])) {
            throw new InvalidConfigurationException('medzuch_jwt.metadata would publish a document without "response_types_supported", which RFC 8414 §2 requires. This bundle cannot fill it in — it describes grants an authorization server runs, not tokens — so name it under "extra".');
        }

        // §2 asks for "a JSON array containing a list of the OAuth 2.0
        // response_type values that this authorization server supports". A key
        // holding null, a bare string or an empty list satisfies the letter of
        // "it is there" and none of that sentence — and each would be served
        // with a 200, which is the outcome refusing the missing key exists to
        // prevent. Which values are right is the application's; that there is
        // at least one, and that they are names, is §2's.
        $responseTypes = $metadata['extra']['response_types_supported'];

        if (!is_array($responseTypes) || !array_is_list($responseTypes) || [] === $responseTypes) {
            throw new InvalidConfigurationException('medzuch_jwt.metadata.extra has a "response_types_supported" that is not a non-empty list. RFC 8414 §2 asks for the response types this server supports, and a document supporting none of them describes nothing.');
        }

        foreach ($responseTypes as $responseType) {
            if (!is_string($responseType) || '' === trim($responseType)) {
                throw new InvalidConfigurationException('medzuch_jwt.metadata.extra has a "response_types_supported" entry that is not a response type name. RFC 8414 §2 asks for OAuth 2.0 response_type values, which are strings.');
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
     * A configured `aud` is either absent or worth checking against.
     *
     * Null is the documented "accept whatever the token names". An empty string
     * is not a third meaning: it reaches the library as an expected audience of
     * `""`, which no token carries, so a receiver written that way looks
     * configured and refuses every delivery.
     *
     * Read through {@see ContainerBuilder::resolveEnvPlaceholders()} rather than
     * judged in the tree, because the tree's `validate()` closures run during
     * ValidateEnvPlaceholdersPass against a dummy empty string — which would
     * refuse `%env(APP_URL)%`, the spelling the README recommends.
     */
    public static function assertAudienceIsUsable(string $context, ?string $audience, ContainerBuilder $builder): void
    {
        if (null === $audience) {
            return;
        }

        $builder->resolveEnvPlaceholders($audience, null, $fromEnvironment);

        if ([] === ($fromEnvironment ?? []) && '' === trim($audience)) {
            throw new InvalidConfigurationException(sprintf('%s has a blank audience; omit it instead, which is how a receiver accepts whatever a token names.', $context));
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

    /**
     * A `dir` key nothing can select is the one way a `jwe_keys` entry is
     * wrong on its own.
     *
     * The library's static resolver takes the `kid` from the header when there
     * is one and otherwise falls back to the header's `alg` — and for direct
     * encryption that `alg` is the literal string `dir`, which no key is ever
     * bound to. So a key that exists to serve `dir` is reachable by `kid` and
     * by nothing else, and one without a `kid` decrypts nothing, ever.
     *
     * The wrapping schemes need no such rule: their keys are bound to the very
     * `alg` the header names, so the fallback finds them.
     *
     * @param array{secret: string, algorithm: string, kid: string|null} $key
     */
    public static function assertJweKeyIsSelectable(string $name, array $key): void
    {
        if (null !== $key['kid'] || !in_array($key['algorithm'], ContentEncryptionAlgorithms::names(), true)) {
            return;
        }

        throw new InvalidConfigurationException(sprintf(
            'JWE key "%s" is bound to %s, which makes it a "dir" key — the Content Encryption Key itself. Such a key is found by its "kid" and by nothing else, so give it one.',
            $name,
            $key['algorithm'],
        ));
    }

    /**
     * Whether a consumer's `jwe` block describes an encrypted token this
     * consumer could ever open (C12).
     *
     * The same two questions {@see assertCanVerify()} asks, in a place where
     * both have an answer: every key named has to exist, and every algorithm
     * allowed has to have a key behind it. A JWE asks two more, because it has
     * two allowlists where a JWS has one — whether every *content* algorithm
     * allowed can be reached, and whether every key can be selected at all. A
     * key ruled out by either list is a rotation that will not happen rather
     * than a spare.
     *
     * `dir` is the awkward one throughout: a key for it is bound to the `enc`
     * it is the Content Encryption Key for, not to the `alg` in the header, so
     * both lists have to be consulted to say whether it can be reached — and
     * it is the reason the content list needs checking at all, since anything
     * that wraps a key wraps one for every `enc` going.
     *
     * @param array{keys: list<string>, allowed_key_management: list<string>, allowed_content_encryption: list<string>} $jwe
     * @param array<string, array{secret: string, algorithm: string, kid: string|null}>                                 $keys
     */
    public static function assertCanDecrypt(string $context, array $jwe, array $keys): void
    {
        $bound = [];

        foreach ($jwe['keys'] as $key) {
            if (!isset($keys[$key])) {
                throw new InvalidConfigurationException(sprintf(
                    '%s decrypts with key "%s", which is not defined under medzuch_jwt.jwe_keys. Defined: %s.',
                    $context,
                    $key,
                    [] === $keys ? 'none' : '"' . implode('", "', array_keys($keys)) . '"',
                ));
            }

            $bound[$key] = $keys[$key]['algorithm'];
        }

        self::assertNamesAreUnique($context, $jwe['keys']);
        self::assertKeysAreDistinguishable($context, array_intersect_key($keys, array_flip($jwe['keys'])), 'encrypted');

        $direct = array_values(array_intersect($bound, $jwe['allowed_content_encryption']));

        foreach ($jwe['allowed_key_management'] as $algorithm) {
            $satisfied = KeyManagementAlgorithms::DIRECT === $algorithm
                ? [] !== $direct
                : in_array($algorithm, $bound, true);

            if (!$satisfied) {
                throw new InvalidConfigurationException(sprintf(
                    '%s allows %s in a token\'s outer header, but none of its JWE keys can be used with it, so such a token could never be decrypted. Its JWE keys are bound to: %s.%s',
                    $context,
                    $algorithm,
                    implode('/', array_unique(array_values($bound))),
                    KeyManagementAlgorithms::DIRECT === $algorithm
                        ? sprintf(' A "dir" key is bound to a content-encryption algorithm this consumer also allows (%s).', implode('/', $jwe['allowed_content_encryption']))
                        : '',
                ));
            }
        }

        // The other direction of the same question, and the one `dir` makes
        // necessary. Any key-wrapping algorithm wraps a Content Encryption Key
        // for any `enc`, so where one of those is allowed and has a key behind
        // it every content algorithm is reachable. Direct encryption has no
        // such freedom: the key *is* the CEK, bound to one `enc` and refused
        // for the others by the library — so where `dir` is the only way in,
        // an `enc` with no key bound to it is a token nothing could open.
        $wrapping = array_values(array_diff($jwe['allowed_key_management'], [KeyManagementAlgorithms::DIRECT]));

        if ([] === $wrapping) {
            foreach ($jwe['allowed_content_encryption'] as $contentEncryption) {
                if (!in_array($contentEncryption, $bound, true)) {
                    throw new InvalidConfigurationException(sprintf(
                        '%s allows %s for the content of a token it decrypts with "dir", and none of its JWE keys is bound to it. A "dir" key is the Content Encryption Key itself, so it serves the one algorithm it names and no other. Its JWE keys are bound to: %s.',
                        $context,
                        $contentEncryption,
                        implode('/', array_unique(array_values($bound))),
                    ));
                }
            }
        }

        foreach ($bound as $key => $algorithm) {
            $reachable = in_array($algorithm, ContentEncryptionAlgorithms::names(), true)
                ? in_array(KeyManagementAlgorithms::DIRECT, $jwe['allowed_key_management'], true) && in_array($algorithm, $jwe['allowed_content_encryption'], true)
                : in_array($algorithm, $jwe['allowed_key_management'], true);

            if (!$reachable) {
                throw new InvalidConfigurationException(sprintf(
                    '%s names JWE key "%s", bound to %s, which nothing it allows can use: a token would have to name %s. Allowed here are %s in the outer header and %s for the content.',
                    $context,
                    $key,
                    $algorithm,
                    in_array($algorithm, ContentEncryptionAlgorithms::names(), true) ? sprintf('"dir" with %s', $algorithm) : $algorithm,
                    implode('/', $jwe['allowed_key_management']),
                    implode('/', $jwe['allowed_content_encryption']),
                ));
            }
        }
    }

    /**
     * Whether an issuer's `jwe` block describes a token it could actually
     * seal (I8).
     *
     * One key and one algorithm of each kind, so there is one question rather
     * than {@see assertCanDecrypt()}'s four: is the key this issuer names made
     * of what the algorithm it names needs? A wrapping key is bound to the
     * `alg` it wraps with; a `dir` key *is* the Content Encryption Key and is
     * bound to the `enc` it is a key for. Getting that wrong builds a green
     * container and throws on the first token minted, which is a 500 on a
     * token endpoint rather than a failed deploy.
     *
     * @param array{key: string, key_management: string, content_encryption: string, replicated_claims: list<string>} $jwe
     * @param array<string, array{secret: string, algorithm: string, kid: string|null}>                               $keys
     */
    public static function assertCanEncrypt(string $context, array $jwe, array $keys): void
    {
        if (!isset($keys[$jwe['key']])) {
            throw new InvalidConfigurationException(sprintf(
                '%s encrypts with key "%s", which is not defined under medzuch_jwt.jwe_keys. Defined: %s.',
                $context,
                $jwe['key'],
                [] === $keys ? 'none' : '"' . implode('", "', array_keys($keys)) . '"',
            ));
        }

        $bound = $keys[$jwe['key']]['algorithm'];
        $needed = KeyManagementAlgorithms::DIRECT === $jwe['key_management']
            ? $jwe['content_encryption']
            : $jwe['key_management'];

        if ($bound === $needed) {
            return;
        }

        throw new InvalidConfigurationException(sprintf(
            '%s encrypts with %s and JWE key "%s", which is bound to %s. %s',
            $context,
            KeyManagementAlgorithms::DIRECT === $jwe['key_management']
                ? sprintf('"dir" and %s', $jwe['content_encryption'])
                : $jwe['key_management'],
            $jwe['key'],
            $bound,
            KeyManagementAlgorithms::DIRECT === $jwe['key_management']
                ? sprintf('A "dir" key is the Content Encryption Key itself, so it has to be a key for %s — name a key bound to it, or encrypt the content with %s.', $jwe['content_encryption'], $bound)
                : sprintf('A key that wraps is bound to the algorithm it wraps with — name a key bound to %s, or wrap with %s.', $jwe['key_management'], $bound),
        ));
    }
}
