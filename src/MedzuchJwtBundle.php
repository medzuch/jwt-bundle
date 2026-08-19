<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle;

use DateInterval;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Profile\AccessTokenConsumer;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Key\KeyLoader;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\AccessTokenSuccessHandler;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * Wires `medzuch/jwt-php` into a Symfony application.
 *
 * `AbstractBundle` derives the configuration root from this class name, so the
 * root key is `medzuch_jwt` and the namespace prefix is `Medzuch\JwtBundle\`.
 * Both are public API: renaming either is a breaking change.
 *
 * @see https://github.com/medzuch/jwt-bundle/blob/main/docs/plan.md the design, the feature catalogue and the roadmap
 */
final class MedzuchJwtBundle extends AbstractBundle
{
    /**
     * Claims {@see \Medzuch\Jwt\Jwt\JwtBuilder::withClaim()} refuses, because
     * each has a typed setter that enforces its shape.
     */
    private const REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    public function configure(DefinitionConfigurator $definition): void
    {
        $root = $definition->rootNode();
        \assert($root instanceof ArrayNodeDefinition);

        $children = $root->children();

        $this->configureGlobals($children);
        $this->configureKeys($children);
        $this->configureIssuers($children);
        $this->configureConsumers($children);
    }

    /**
     * The shape below is what the tree in {@see self::configure()} guarantees;
     * `$config` arrives untyped because the parent signature says `array`.
     *
     * @param array<array-key, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        /** @var array{
         *     clock: string|null,
         *     logger: string|null,
         *     keys: array<string, array{hmac?: string, pem_private?: string, pem_public?: string, pem_passphrase?: string, algorithm: string, kid: string|null}>,
         *     issuers: array<string, array{issuer: string, key: string, client_id: string, ttl: int, audience: list<string>, claims: array<string, mixed>}>,
         *     consumers: array<string, array{issuer: string, audience: list<string>, keys: list<string>, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}>,
         * } $config */
        $container->import('../config/services.yaml');

        if (null !== $config['clock']) {
            // setAlias() drops the definition from services.php, so the
            // container holds exactly one medzuch_jwt.clock either way.
            $builder->setAlias('medzuch_jwt.clock', $config['clock']);
        }

        $keys = $this->keyEntries($config['keys']);

        $services = $container->services();
        $this->registerKeys($services, $keys);
        $this->registerIssuers($services, $keys, $config['issuers']);
        $this->registerConsumers($services, $keys, $config['consumers'], $config['logger']);
    }

    private function configureGlobals(NodeBuilder $children): void
    {
        $children->scalarNode('clock')
            ->defaultNull()
            ->info('Service id of a PSR-20 clock. Null uses the library\'s SystemClock.')
            ->example('app.frozen_clock')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => null !== $value && (!\is_string($value) || '' === trim($value)))
                ->thenInvalid('medzuch_jwt.clock must be a non-empty service id, got %s')
            ->end();

        $children->scalarNode('logger')
            ->defaultNull()
            ->info('Service id of a PSR-3 logger. Null disables logging entirely.')
            ->example('monolog.logger.jwt')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => null !== $value && (!\is_string($value) || '' === trim($value)))
                ->thenInvalid('medzuch_jwt.logger must be a non-empty service id, got %s')
            ->end();
    }

    private function configureKeys(NodeBuilder $children): void
    {
        $key = $children->arrayNode('keys')
            ->info('Named keys, referenced by name from consumers and issuers.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        self::declareKeySource(
            $key,
            'hmac',
            'Shared secret, at least 32/48/64 bytes for HS256/384/512 (RFC 8725 §3.5). Use an env reference; %env(base64:NAME)% decodes a base64 secret. The length cannot be checked at build: the secret stays an env reference so it never reaches a container parameter, so a short one fails when the key is first used.',
            '%env(JWT_SECRET)%',
        );

        self::declareKeySource(
            $key,
            'pem_private',
            'Signing key: a path to a PEM file, or the PEM itself. Told apart by the armour, so a value beginning with -----BEGIN is read as the key rather than as a filename.',
            '%kernel.project_dir%/config/jwt/private.pem',
        );

        self::declareKeySource(
            $key,
            'pem_public',
            'Verification key, same two spellings. A consumer needs this half; the private one cannot stand in for it.',
            '%kernel.project_dir%/config/jwt/public.pem',
        );

        self::declareKeySource(
            $key,
            'pem_passphrase',
            'Passphrase for an encrypted private PEM. Use an env reference.',
            '%env(JWT_KEY_PASSPHRASE)%',
        );

        $key->enumNode('algorithm')
            ->values(SigningAlgorithms::names())
            ->defaultValue('HS256')
            ->info('The algorithm this key is bound to. A key verifies nothing else, and the algorithm decides what material the key must be.')
            ->end();

        $key->scalarNode('kid')
            ->defaultNull()
            ->info('Key id published in the token header. Required once two keys share an algorithm.')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => '' === $value)
                ->thenInvalid('A key\'s "kid" cannot be the empty string; omit it instead.')
            ->end()
            ->end();
    }

    private function configureIssuers(NodeBuilder $children): void
    {
        $issuer = $children->arrayNode('issuers')
            ->info('Named issuers. Each mints tokens with exactly one key.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $issuer->scalarNode('issuer')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Value of the `iss` claim, and what a consumer must expect.')
            ->end();

        $issuer->scalarNode('key')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Name from the `keys` section. Its algorithm is the signing algorithm — a key is bound to one, so restating it here could only disagree.')
            ->end();

        $issuer->scalarNode('client_id')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Value of the `client_id` claim, required by RFC 9068 §2.2.')
            ->end();

        $issuer->integerNode('ttl')
            ->defaultValue(900)
            ->min(1)
            ->info('Token lifetime in seconds. Short is the point: a bearer token cannot be recalled.')
            ->end();

        $audience = $issuer->arrayNode('audience');
        $audience->info('Value of the `aud` claim.');
        $audience->beforeNormalization()->castToArray()->end();
        $audience->scalarPrototype()->cannotBeEmpty()->end();
        $audience->isRequired();
        $audience->requiresAtLeastOneElement();
        self::rejectMaps($audience, 'audience');

        $claims = $issuer->arrayNode('claims');
        $claims->info('Static claims added to every token. A caller can override one; the profile\'s own claims cannot be overridden by either.');
        $claims->normalizeKeys(false);
        $claims->useAttributeAsKey('name');
        $claims->variablePrototype()->end();
        // The library routes registered claims through typed setters and
        // refuses them here, so this configuration would build a green
        // container and throw on the first token minted.
        $claims->validate()
            ->ifTrue(static fn(mixed $value): bool => is_array($value) && [] !== array_intersect(array_keys($value), self::REGISTERED_CLAIMS))
            ->thenInvalid(sprintf(
                'Static claims cannot include the registered claims %s — they are set from configuration (`issuer`, `audience`, `ttl`) or by the profile. Got %%s',
                '"' . implode('", "', self::REGISTERED_CLAIMS) . '"',
            ))
            ->end();
    }

    private function configureConsumers(NodeBuilder $children): void
    {
        $consumer = $children->arrayNode('consumers')
            ->info('Named consumers. A firewall names one through token_handler.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $consumer->scalarNode('issuer')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('The only `iss` this consumer accepts.')
            ->end();

        // Each node is held in a variable rather than chained: NodeDefinition
        // methods return the base type or a nullable parent, so a fluent chain
        // loses ArrayNodeDefinition after the first hop.
        $audience = $consumer->arrayNode('audience');
        $audience->info('Identifiers this resource server answers to. A token is accepted when its `aud` names any of them.');
        $audience->beforeNormalization()->castToArray()->end();
        $audience->scalarPrototype()->cannotBeEmpty()->end();
        $audience->isRequired();
        $audience->requiresAtLeastOneElement();
        self::rejectMaps($audience, 'audience');

        $keys = $consumer->arrayNode('keys');
        $keys->info('Names from the `keys` section. Verification tries the key the token names, or the one bound to its algorithm.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        $keys->isRequired();
        $keys->requiresAtLeastOneElement();
        self::rejectMaps($keys, 'keys');

        $algorithms = $consumer->arrayNode('allowed_algorithms');
        $algorithms->info('JOSE `alg` values accepted. Anything else is refused before a signature is checked.');
        $algorithms->enumPrototype()->values(SigningAlgorithms::names())->end();
        $algorithms->isRequired();
        $algorithms->requiresAtLeastOneElement();
        self::rejectMaps($algorithms, 'allowed_algorithms');

        $consumer->integerNode('leeway')
            ->defaultValue(0)
            ->min(0)
            ->max(ValidatorBuilder::LEEWAY_CEILING_SECONDS)
            ->info('Clock-skew tolerance in seconds for exp/nbf/iat. The ceiling is the library\'s.')
            ->end();

        $user = $consumer->arrayNode('user')
            ->addDefaultsIfNotSet()
            ->children();

        $user->scalarNode('identity_claim')
            ->defaultValue('sub')
            ->cannotBeEmpty()
            ->info('Claim whose value is handed to the user provider as the user identifier.')
            ->end();
    }

    /**
     * Key sources carry no default: an optional scalar without one is simply
     * absent from the normalised configuration, which {@see self::keyEntries()}
     * fills in. A null default plus a hand-written emptiness check would read
     * more directly, but a `validate()` closure also runs against the sample
     * values Symfony substitutes for an `%env()%` reference — so it would
     * reject every environment-backed secret. `cannotBeEmpty()` knows about
     * placeholders and does not.
     */
    private static function declareKeySource(NodeBuilder $key, string $name, string $info, string $example): void
    {
        $key->scalarNode($name)
            ->cannotBeEmpty()
            ->info($info)
            ->example($example)
            ->end();
    }

    /**
     * @param array<string, array{hmac?: string, pem_private?: string, pem_public?: string, pem_passphrase?: string, algorithm: string, kid: string|null}> $keys
     *
     * @return array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>
     */
    private function keyEntries(array $keys): array
    {
        $entries = [];

        foreach ($keys as $name => $key) {
            $entries[$name] = [
                'hmac' => $key['hmac'] ?? null,
                'pem_private' => $key['pem_private'] ?? null,
                'pem_public' => $key['pem_public'] ?? null,
                'pem_passphrase' => $key['pem_passphrase'] ?? null,
                'algorithm' => $key['algorithm'],
                'kid' => $key['kid'],
            ];
        }

        return $entries;
    }

    /**
     * A list-shaped node must not be given a YAML map. Symfony's prototyped
     * array nodes accept arbitrary keys, and the library refuses an associative
     * array — but it refuses it inside a lazily built service, which makes a
     * configuration mistake arrive as a 500 on the first request, phrased as a
     * problem with the token.
     */
    private static function rejectMaps(ArrayNodeDefinition $node, string $name): void
    {
        $node->validate()
            ->ifTrue(static fn(mixed $value): bool => is_array($value) && !array_is_list($value))
            ->thenInvalid(sprintf('medzuch_jwt consumer "%s" must be a sequence, not a map. Got %%s', $name))
            ->end();
    }

    /**
     * Key resolution is first-match-wins in both directions and never falls
     * back: {@see \Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver} matches a
     * header `kid` exactly or throws, and a `kid`-less header takes the first
     * key bound to the token's algorithm. So two keys a token cannot tell apart
     * — sharing a `kid`, or sharing an algorithm with no `kid` at all — mean the
     * second one verifies nothing, and rotation silently invalidates every
     * token still in flight (DEC-5).
     *
     * The ambiguity is a property of one verification set, not of the
     * configuration as a whole: the resolver only ever sees the keys of the
     * consumer doing the verifying. Checking globally would reject the most
     * ordinary asymmetric setup there is — a private entry and a public entry
     * that are two halves of one keypair, bound to the same algorithm and
     * carrying the same `kid` precisely because they are the same key.
     *
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
     */
    private function assertKeysAreDistinguishable(string $consumer, array $keys): void
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
                    'Consumer "%s" verifies with keys "%s", all bound to %s with no "kid", so a token cannot say which one signed it. Give each of them a kid.',
                    $consumer,
                    implode('", "', $names),
                    $algorithm,
                ));
            }
        }

        foreach ($namesByKid as $kid => $names) {
            if (count($names) > 1) {
                throw new InvalidConfigurationException(sprintf(
                    'Consumer "%s" verifies with keys "%s", which share the kid "%s". A token naming it is verified against the first of them and never the others.',
                    $consumer,
                    implode('", "', $names),
                    $kid,
                ));
            }
        }
    }

    /**
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
     */
    private function registerKeys(ServicesConfigurator $services, array $keys): void
    {
        foreach ($keys as $name => $key) {
            $this->assertKeyMaterialMatchesAlgorithm($name, $key);

            // Key material stays an env reference or a path all the way into
            // the factory argument, and the factory runs when the service is
            // built: resolved at compile time it would sit in the compiled
            // container and in `debug:container` output (K9).
            if (null !== $key['hmac']) {
                // A symmetric key is both halves at once, so signing and
                // verification resolve to the same object.
                $services->set('medzuch_jwt.key.' . $name, HmacKey::class)
                    ->factory([HmacKey::class, 'fromBinary'])
                    ->args([$key['hmac'], $key['algorithm'], $key['kid']]);

                // Both roles answer by name, so every call site reads the same
                // whether the key is symmetric or not.
                $services->alias('medzuch_jwt.key.' . $name . '.signing', 'medzuch_jwt.key.' . $name);
                $services->alias('medzuch_jwt.key.' . $name . '.verification', 'medzuch_jwt.key.' . $name);

                continue;
            }

            if (null !== $key['pem_private']) {
                $services->set('medzuch_jwt.key.' . $name, KeyLoader::signingKeyClass($key['algorithm']))
                    ->factory([KeyLoader::class, 'signingKey'])
                    ->args([$key['pem_private'], $key['algorithm'], $key['kid'], $key['pem_passphrase']]);

                $services->alias('medzuch_jwt.key.' . $name . '.signing', 'medzuch_jwt.key.' . $name);
            }

            if (null !== $key['pem_public']) {
                $services->set('medzuch_jwt.key.' . $name . '.verification', KeyLoader::verificationKeyClass($key['algorithm']))
                    ->factory([KeyLoader::class, 'verificationKey'])
                    ->args([$key['pem_public'], $key['algorithm'], $key['kid']]);
            }
        }
    }

    /**
     * A key entry names exactly one kind of material, and the algorithm decides
     * which kind it must be — an RSA algorithm cannot be given a shared secret,
     * and HS256 cannot be given a PEM. Both would fail when the key is first
     * built, deep in the library, describing the material rather than the
     * configuration that chose it.
     *
     * @param array{hmac: string|null, pem_private: string|null, pem_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null} $key
     */
    private function assertKeyMaterialMatchesAlgorithm(string $name, array $key): void
    {
        $family = SigningAlgorithms::familyOf($key['algorithm']);
        $hasPem = null !== $key['pem_private'] || null !== $key['pem_public'];

        if (null !== $key['hmac'] && $hasPem) {
            throw new InvalidConfigurationException(sprintf('Key "%s" gives both a shared secret and a PEM. A key is one thing.', $name));
        }

        if (null === $key['hmac'] && !$hasPem) {
            throw new InvalidConfigurationException(sprintf('Key "%s" has no material: give it "hmac", or "pem_private" and/or "pem_public".', $name));
        }

        if (SigningAlgorithms::FAMILY_HMAC === $family && $hasPem) {
            throw new InvalidConfigurationException(sprintf('Key "%s" is bound to %s, which takes a shared secret, not a PEM. Set "algorithm" to an RSA or EC one.', $name, $key['algorithm']));
        }

        if (SigningAlgorithms::FAMILY_HMAC !== $family && null !== $key['hmac']) {
            throw new InvalidConfigurationException(sprintf('Key "%s" is bound to %s, which needs a PEM, not a shared secret. The shared-secret algorithms are %s.', $name, $key['algorithm'], implode('/', SigningAlgorithms::namesForFamily(SigningAlgorithms::FAMILY_HMAC))));
        }

        if (SigningAlgorithms::FAMILY_OKP === $family) {
            throw new InvalidConfigurationException(sprintf('Key "%s" is bound to EdDSA, which has no PEM representation in this release; a JWK key source is planned.', $name));
        }

        if (null !== $key['pem_passphrase'] && null === $key['pem_private']) {
            throw new InvalidConfigurationException(sprintf('Key "%s" has a passphrase but no "pem_private" to unlock.', $name));
        }
    }

    /**
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                    $keys
     * @param array<string, array{issuer: string, key: string, client_id: string, ttl: int, audience: list<string>, claims: array<string, mixed>}> $issuers
     */
    private function registerIssuers(ServicesConfigurator $services, array $keys, array $issuers): void
    {
        foreach ($issuers as $name => $issuer) {
            if (!isset($keys[$issuer['key']])) {
                throw new InvalidConfigurationException(sprintf(
                    'Issuer "%s" signs with key "%s", which is not defined under medzuch_jwt.keys. Defined: %s.',
                    $name,
                    $issuer['key'],
                    [] === $keys ? 'none' : '"' . implode('", "', array_keys($keys)) . '"',
                ));
            }

            if (null === $keys[$issuer['key']]['hmac'] && null === $keys[$issuer['key']]['pem_private']) {
                throw new InvalidConfigurationException(sprintf(
                    'Issuer "%s" signs with key "%s", which has only a public PEM. Signing needs the private half.',
                    $name,
                    $issuer['key'],
                ));
            }

            $services->set('medzuch_jwt.issuer.' . $name . '.profile', AccessTokenProfile::class)
                ->factory([AccessTokenProfile::class, 'issuer'])
                ->args([
                    $issuer['issuer'],
                    inline_service(SigningAlgorithms::CLASSES[$keys[$issuer['key']]['algorithm']]),
                    service('medzuch_jwt.key.' . $issuer['key'] . '.signing'),
                    service('medzuch_jwt.clock'),
                ]);

            $services->set('medzuch_jwt.issuer.' . $name, AccessTokenIssuer::class)
                ->args([
                    service('medzuch_jwt.issuer.' . $name . '.profile'),
                    array_values($issuer['audience']),
                    $issuer['client_id'],
                    $issuer['ttl'],
                    $issuer['claims'],
                ]);

            $services->set('medzuch_jwt.login.' . $name, AccessTokenSuccessHandler::class)
                ->args([service('medzuch_jwt.issuer.' . $name)]);
        }

        // Autowiring reaches the `default` issuer by type. Applications with
        // several issuers name the service they want; one issuer is the common
        // case and should not have to.
        if (isset($issuers['default'])) {
            $services->alias(AccessTokenIssuer::class, 'medzuch_jwt.issuer.default');
        }
    }

    /**
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                                              $keys
     * @param array<string, array{issuer: string, audience: list<string>, keys: list<string>, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}> $consumers
     */
    private function registerConsumers(ServicesConfigurator $services, array $keys, array $consumers, ?string $logger): void
    {
        foreach ($consumers as $name => $consumer) {
            $this->assertConsumerCanVerify($name, $consumer, $keys);

            $services->set('medzuch_jwt.jwk_set.' . $name, JwkSet::class)
                ->factory([JwkSet::class, 'of'])
                ->args(array_map(static fn(string $key): mixed => service('medzuch_jwt.key.' . $key . '.verification'), array_values($consumer['keys'])));

            $services->set('medzuch_jwt.consumer.' . $name, AccessTokenConsumer::class)
                ->factory([AccessTokenProfile::class, 'consumer'])
                ->args([
                    $consumer['issuer'],
                    array_values($consumer['audience']),
                    service('medzuch_jwt.jwk_set.' . $name),
                    array_map(static fn(string $alg): mixed => inline_service(SigningAlgorithms::CLASSES[$alg]), array_values($consumer['allowed_algorithms'])),
                    service('medzuch_jwt.clock'),
                    null === $logger ? null : service($logger),
                    null,
                    0 === $consumer['leeway'] ? null : inline_service(DateInterval::class)->args([sprintf('PT%dS', $consumer['leeway'])]),
                ]);

            $services->set('medzuch_jwt.handler.' . $name, AccessTokenHandler::class)
                ->args([service('medzuch_jwt.consumer.' . $name), $consumer['user']['identity_claim']]);
        }
    }

    /**
     * @param array{issuer: string, audience: list<string>, keys: list<string>, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}} $consumer
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                              $keys
     */
    private function assertConsumerCanVerify(string $name, array $consumer, array $keys): void
    {
        $bound = [];

        foreach ($consumer['keys'] as $key) {
            if (!isset($keys[$key])) {
                throw new InvalidConfigurationException(sprintf(
                    'Consumer "%s" names key "%s", which is not defined under medzuch_jwt.keys. Defined: %s.',
                    $name,
                    $key,
                    [] === $keys ? 'none' : '"' . implode('", "', array_keys($keys)) . '"',
                ));
            }

            if (null === $keys[$key]['hmac'] && null === $keys[$key]['pem_public']) {
                throw new InvalidConfigurationException(sprintf(
                    'Consumer "%s" verifies with key "%s", which has only a private PEM. Verification needs the public half — a private key cannot stand in for it.',
                    $name,
                    $key,
                ));
            }

            $bound[] = $keys[$key]['algorithm'];
        }

        $this->assertKeysAreDistinguishable($name, array_intersect_key($keys, array_flip($consumer['keys'])));

        // Every allowed algorithm must have a key behind it, not merely one of
        // them: an algorithm on the allowlist that no key can verify is a
        // permanently dead branch, and the usual way to get one is asking for
        // an algorithm this release has no key source for. The check holds
        // while every key source is static; remote JWKS (K5) publishes its
        // algorithms at runtime and will need its own reading of "satisfied".
        $unsatisfied = array_values(array_diff($consumer['allowed_algorithms'], $bound));

        if ([] !== $unsatisfied) {
            throw new InvalidConfigurationException(sprintf(
                'Consumer "%s" allows %s, but none of its keys is bound to %s, so a token using it could never be verified. Its keys are bound to: %s.',
                $name,
                implode('/', $unsatisfied),
                1 === count($unsatisfied) ? 'it' : 'them',
                implode('/', array_unique($bound)),
            ));
        }
    }
}
