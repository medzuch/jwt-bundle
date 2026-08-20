<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle;

use DateInterval;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\CompositeResolver;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Profile\AccessTokenConsumer;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Medzuch\JwtBundle\Command\GenerateKeyCommand;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Jwks\JwksController;
use Medzuch\JwtBundle\Key\KeyLoader;
use Medzuch\JwtBundle\Oidc\IdTokenVerifier;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\AccessTokenSuccessHandler;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Console\Command\Command;
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
        $this->configureRemoteJwks($children);
        $this->configureIssuers($children);
        $this->configureConsumers($children);
        $this->configureIdTokens($children);
        $this->configureJwks($children);
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
         *     keys: array<string, array{hmac?: string, pem_private?: string, pem_public?: string, jwk_private?: string, jwk_public?: string, pem_passphrase?: string, algorithm: string, kid: string|null}>,
         *     issuers: array<string, array{issuer: string, key: string, client_id: string, ttl: int, audience: list<string>, claims: array<string, mixed>}>,
         *     jwks: array{keys: list<string>, cache_max_age: int},
         *     remote_jwks: array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>,
         *     consumers: array<string, array{issuer: string, audience: list<string>, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}>,
         *     id_tokens: array<string, array{issuer: string, client_id: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, leeway: int}>,
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
        $this->registerRemoteJwks($services, $builder, $config['remote_jwks'], $config['logger']);
        $this->registerIssuers($services, $keys, $config['issuers']);
        $this->registerConsumers($services, $keys, $config['consumers'], $config['remote_jwks'], $config['logger']);
        $this->registerIdTokens($services, $builder, $keys, $config['id_tokens'], $config['remote_jwks'], $config['logger']);
        $this->registerJwks($services, $keys, $config['jwks']);
        $this->registerConsoleCommands($services);
    }

    /**
     * The console is a dependency of applications, not of bundles: a worker
     * image that installs neither `symfony/console` nor a way to run it is a
     * normal way to deploy this bundle, and a service definition for a class
     * that cannot be loaded would break its container for a command it can
     * never run.
     */
    private function registerConsoleCommands(ServicesConfigurator $services): void
    {
        if (!class_exists(Command::class)) {
            return;
        }

        $services->set('medzuch_jwt.command.key_generate', GenerateKeyCommand::class)
            ->tag('console.command', ['command' => 'jwt:key:generate']);
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
            'jwk_private',
            'Signing key as a JWK: a path to a JSON file, or the JSON itself. The only source for EdDSA, which has no PEM representation. What the document states — "alg", "kid", "use" — has to agree with what is configured here.',
            '%kernel.project_dir%/config/jwt/private.jwk.json',
        );

        self::declareKeySource(
            $key,
            'jwk_public',
            'Verification key as a JWK, same two spellings. A document carrying "d" is refused: that is the private half, and the JWKS endpoint would publish it.',
            '%kernel.project_dir%/config/jwt/public.jwk.json',
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

    /**
     * A key set the bundle does not hold: an issuer publishes it, the
     * application fetches it. Named at the top level rather than spelled out
     * inside a consumer, because two consumers of the same identity provider
     * are the ordinary case and they should share one cache entry and one
     * refresh window, not race each other for them.
     */
    private function configureRemoteJwks(NodeBuilder $children): void
    {
        $set = $children->arrayNode('remote_jwks')
            ->info('Named remote JWK Sets, referenced by name from consumers.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $set->scalarNode('uri')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('The issuer\'s `jwks_uri`. HTTPS only: fetching verification keys over a channel an attacker can rewrite defeats the point (RFC 8725 §3.10). Never taken from a token\'s `jku`.')
            ->example('https://idp.example.com/.well-known/jwks.json')
            ->end();

        $set->scalarNode('http_client')
            ->defaultValue('psr18.http_client')
            ->cannotBeEmpty()
            ->info('Service id of a PSR-18 client. Symfony registers `psr18.http_client` once `psr/http-client` is installed and `framework.http_client` is enabled. Connection and response timeouts belong to the client: this bundle cannot impose a socket timeout on one it does not own.')
            ->end();

        self::declareOptionalName(
            $set,
            'request_factory',
            'Service id of a PSR-17 request factory. Null uses the client, which is right for Symfony\'s `psr18.http_client` — it is a factory as well — and wrong for a client that is not.',
            'nyholm.psr7.psr17_factory',
        );

        self::declareOptionalName($set, 'cache_pool', 'Service id of a PSR-6 cache pool, wrapped for the PSR-16 interface the resolver takes. This is the Symfony-shaped answer: `cache.app` is a pool.', 'cache.app');
        self::declareOptionalName($set, 'cache', 'Service id of a PSR-16 cache, used as it is. For an application that already has one; otherwise use "cache_pool".', 'app.jwks_cache');

        // The library refuses zero for all three, and it is right to: a
        // lifetime of zero is a fetch per token, and a refresh window of zero
        // is the amplifier the window exists to prevent. `min(1)` says so here
        // rather than letting a configuration the tree accepted fail inside a
        // service factory.
        $set->integerNode('cache_ttl')
            ->defaultValue(300)
            ->min(1)
            ->info('Seconds the fetched document is cached. The common path never touches the network. Zero is refused: it would fetch the set for every token.')
            ->end();

        $set->integerNode('min_refresh')
            ->defaultValue(60)
            ->min(1)
            ->info('Shortest interval between refetches when a token names a `kid` the cached set does not have. Without it, a stream of tokens bearing unknown kids is an amplifier pointed at the issuer.')
            ->end();

        $set->integerNode('max_body_bytes')
            ->defaultValue(256 * 1024)
            ->min(1)
            ->info('Responses larger than this are refused before parsing, so a hostile or broken endpoint cannot exhaust memory.')
            ->end();
    }

    /**
     * An optional reference to something named elsewhere — a service id, or a
     * name from another section.
     *
     * `cannotBeEmpty()` is not what these want: null is their default and
     * their way of saying "not configured", and `cannotBeEmpty()` refuses it
     * when written out, so `remote_jwks: ~` would fail with a message about
     * emptiness rather than being the no-op it reads as. What is refused is a
     * blank string, which is a name nobody meant to write.
     */
    private static function declareOptionalName(NodeBuilder $node, string $name, string $info, string $example): void
    {
        $node->scalarNode($name)
            ->defaultNull()
            ->info($info)
            ->example($example)
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && '' === trim($value))
                ->thenInvalid('medzuch_jwt.' . $name . ' cannot be blank; omit it instead. Got %s')
            ->end()
            ->end();
    }

    /**
     * An OIDC relying-party registration: which provider, which client, and
     * what to verify their ID tokens with.
     *
     * Separate from `consumers` rather than a mode of it, because the two
     * produce different things. A consumer is wired into a firewall; an ID
     * token is not a bearer credential and gets no handler, so putting them in
     * one section would make the wrong wiring a one-word change.
     */
    private function configureIdTokens(NodeBuilder $children): void
    {
        $idToken = $children->arrayNode('id_tokens')
            ->info('Named OIDC relying-party registrations. Each verifies ID tokens from one provider, for one client.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $idToken->scalarNode('issuer')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('The only `iss` accepted, exactly as the provider publishes it.')
            ->example('https://idp.example.com')
            ->end();

        $idToken->scalarNode('client_id')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('This application\'s client id at the provider. It is the audience an ID token must name, and the `azp` it must name when it names more than one (OIDC Core §3.1.3.7).')
            ->example('%env(OIDC_CLIENT_ID)%')
            ->end();

        $keys = $idToken->arrayNode('keys');
        $keys->info('Names from the `keys` section. Optional only when "remote_jwks" is given; with both, these are tried first.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        self::rejectMaps($keys, 'id_tokens.*.keys');

        self::declareOptionalName(
            $idToken,
            'remote_jwks',
            'Name from the `remote_jwks` section. The ordinary way to verify a provider\'s ID tokens: they rotate their keys on their own schedule.',
            'partner_idp',
        );

        $algorithms = $idToken->arrayNode('allowed_algorithms');
        $algorithms->info('JOSE `alg` values accepted. Anything else is refused before a signature is checked.');
        $algorithms->enumPrototype()->values(SigningAlgorithms::names())->end();
        $algorithms->isRequired();
        $algorithms->requiresAtLeastOneElement();
        self::rejectMaps($algorithms, 'id_tokens.*.allowed_algorithms');

        $idToken->integerNode('leeway')
            ->defaultValue(0)
            ->min(0)
            ->max(ValidatorBuilder::LEEWAY_CEILING_SECONDS)
            ->info('Clock-skew tolerance in seconds for exp/nbf/iat. The ceiling is the library\'s.')
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
        self::rejectMaps($audience, 'issuers.*.audience');

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

    private function configureJwks(NodeBuilder $children): void
    {
        $jwks = $children->arrayNode('jwks')
            ->info('Public keys to publish as a JWK Set. The application routes to medzuch_jwt.jwks_controller itself; where the document lives is its decision.')
            ->addDefaultsIfNotSet();

        $jwksChildren = $jwks->children();

        $keys = $jwksChildren->arrayNode('keys');
        $keys->info('Names from the `keys` section. Only verification halves are published, and never a shared secret.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        $keys->defaultValue([]);
        self::rejectMaps($keys, 'jwks.keys');

        $jwksChildren->integerNode('cache_max_age')
            ->defaultValue(300)
            ->min(0)
            ->info('Seconds a relying party may cache the document. The response carries an ETag, so zero means revalidate — a conditional request gets 304 — rather than refetch. A rotation needs neither: an accepted key stays accepted for as long as it is configured.')
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
        self::rejectMaps($audience, 'consumers.*.audience');

        $keys = $consumer->arrayNode('keys');
        $keys->info('Names from the `keys` section. Verification tries the key the token names, or the one bound to its algorithm. Optional only when "remote_jwks" is given; with both, these are tried first and the network is never touched for a key already here.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        self::rejectMaps($keys, 'consumers.*.keys');

        self::declareOptionalName(
            $consumer,
            'remote_jwks',
            'Name from the `remote_jwks` section: an issuer\'s published key set, fetched and cached rather than configured. Keys the issuer rotates to are picked up without a deploy.',
            'partner_idp',
        );

        $algorithms = $consumer->arrayNode('allowed_algorithms');
        $algorithms->info('JOSE `alg` values accepted. Anything else is refused before a signature is checked.');
        $algorithms->enumPrototype()->values(SigningAlgorithms::names())->end();
        $algorithms->isRequired();
        $algorithms->requiresAtLeastOneElement();
        self::rejectMaps($algorithms, 'consumers.*.allowed_algorithms');

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
     * @param array<string, array{hmac?: string, pem_private?: string, pem_public?: string, jwk_private?: string, jwk_public?: string, pem_passphrase?: string, algorithm: string, kid: string|null}> $keys
     *
     * @return array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>
     */
    private function keyEntries(array $keys): array
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
     * The same name twice is always a mistake and never a rotation: it puts one
     * key in a set twice, which no resolver anywhere benefits from.
     *
     * @param list<string> $names
     */
    private static function assertNamesAreUnique(string $context, array $names): void
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
            ->thenInvalid(sprintf('medzuch_jwt.%s must be a sequence, not a map. Got %%s', $name))
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
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
     */
    private function assertKeysAreDistinguishable(string $context, array $keys): void
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
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
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

            if (null !== $key['jwk_private']) {
                $services->set('medzuch_jwt.key.' . $name, KeyLoader::signingKeyClass($key['algorithm']))
                    ->factory([KeyLoader::class, 'signingKeyFromJwk'])
                    ->args([$key['jwk_private'], $key['algorithm'], $key['kid']]);

                $services->alias('medzuch_jwt.key.' . $name . '.signing', 'medzuch_jwt.key.' . $name);
            }

            if (null !== $key['pem_public']) {
                $services->set('medzuch_jwt.key.' . $name . '.verification', KeyLoader::verificationKeyClass($key['algorithm']))
                    ->factory([KeyLoader::class, 'verificationKey'])
                    ->args([$key['pem_public'], $key['algorithm'], $key['kid']]);
            }

            if (null !== $key['jwk_public']) {
                $services->set('medzuch_jwt.key.' . $name . '.verification', KeyLoader::verificationKeyClass($key['algorithm']))
                    ->factory([KeyLoader::class, 'verificationKeyFromJwk'])
                    ->args([$key['jwk_public'], $key['algorithm'], $key['kid']]);
            }
        }
    }

    /**
     * Which halves a key entry has, whatever the material is spelled as. A
     * shared secret is both halves at once; a PEM or JWK pair is whichever of
     * the two it was given.
     *
     * @param array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null} $key
     */
    private static function hasPrivateHalf(array $key): bool
    {
        return null !== $key['hmac'] || null !== $key['pem_private'] || null !== $key['jwk_private'];
    }

    /**
     * @param array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null} $key
     */
    private static function hasPublicHalf(array $key): bool
    {
        return null !== $key['hmac'] || null !== $key['pem_public'] || null !== $key['jwk_public'];
    }

    /**
     * One resolver per named set, so consumers of the same issuer share a
     * cache entry and a refresh window instead of each keeping their own.
     *
     * Nothing is fetched while the container is built — the resolver is
     * constructed with a URI and fetches on the first token that needs a key
     * (K9's reasoning, extended: a build that reaches the network fails when
     * the network does, and bakes whatever it found into the compiled
     * container).
     *
     * @param array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}> $sets
     */
    private function registerRemoteJwks(ServicesConfigurator $services, ContainerBuilder $builder, array $sets, ?string $logger): void
    {
        foreach ($sets as $name => $set) {
            self::assertRemoteJwksIsUsable($name, $set, $builder);

            $services->set('medzuch_jwt.remote_jwks.' . $name, RemoteJwksResolver::class)
                ->args([
                    $set['uri'],
                    service($set['http_client']),
                    // Symfony's PSR-18 client is a PSR-17 factory too, which is
                    // why the default is the client itself rather than a second
                    // service id every application would have to name.
                    service($set['request_factory'] ?? $set['http_client']),
                    self::cacheReference($set),
                    service('medzuch_jwt.clock'),
                    $set['cache_ttl'],
                    $set['min_refresh'],
                    $set['max_body_bytes'],
                    null === $logger ? null : service($logger),
                ]);
        }
    }

    /**
     * @param array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int} $set
     */
    private static function cacheReference(array $set): mixed
    {
        if (null !== $set['cache']) {
            return service($set['cache']);
        }

        return inline_service(Psr16Cache::class)->args([service($set['cache_pool'] ?? 'cache.app')]);
    }

    /**
     * @param array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int} $set
     */
    private static function assertRemoteJwksIsUsable(string $name, array $set, ContainerBuilder $builder): void
    {
        if (null !== $set['cache'] && null !== $set['cache_pool']) {
            throw new InvalidConfigurationException(sprintf('Remote JWK Set "%s" names both a PSR-16 cache and a PSR-6 pool. Give one: "cache" is used as it is, "cache_pool" is wrapped.', $name));
        }

        // The same test the library makes, in the same direction: everything
        // that is not https is refused, rather than the one spelling of
        // plaintext that comes to mind. "HTTP://", "ftp://" and a bare host are
        // all not-https, and a check that named only "http://" would let each
        // of them reach the first token before failing.
        //
        // A URI assembled from the environment is exempt because there is
        // nothing to read yet: it is a placeholder until the container is
        // compiled, and the library refuses a plaintext one when the resolver
        // is built.
        $builder->resolveEnvPlaceholders($set['uri'], null, $fromEnvironment);

        if ([] === ($fromEnvironment ?? []) && 0 !== stripos($set['uri'], 'https://')) {
            throw new InvalidConfigurationException(sprintf('Remote JWK Set "%s" has a jwks_uri that is not https. Verification keys taken from a channel an attacker can rewrite are not verification keys (RFC 8725 §3.10). Got "%s".', $name, $set['uri']));
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
    private function assertKeyMaterialMatchesAlgorithm(string $name, array $key): void
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
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                    $keys
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

            if (!self::hasPrivateHalf($keys[$issuer['key']])) {
                throw new InvalidConfigurationException(sprintf(
                    'Issuer "%s" signs with key "%s", which has only a public half. Signing needs the private half.',
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
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
     * @param array{keys: list<string>, cache_max_age: int}                                                                                                              $jwks
     */
    private function registerJwks(ServicesConfigurator $services, array $keys, array $jwks): void
    {
        if ([] === $jwks['keys']) {
            return;
        }

        foreach ($jwks['keys'] as $name) {
            if (!isset($keys[$name])) {
                throw new InvalidConfigurationException(sprintf(
                    'medzuch_jwt.jwks publishes key "%s", which is not defined under medzuch_jwt.keys.',
                    $name,
                ));
            }

            // The one refusal this endpoint exists to make. A symmetric key's
            // JWK carries `k`, so publishing it hands every reader the key that
            // signs — and it would be a fully valid JWK Set, served with a 200.
            if (null !== $keys[$name]['hmac']) {
                throw new InvalidConfigurationException(sprintf(
                    'medzuch_jwt.jwks would publish key "%s", which is a shared secret. Its JWK carries the secret itself, so publishing it gives away the key that signs.',
                    $name,
                ));
            }

            if (!self::hasPublicHalf($keys[$name])) {
                throw new InvalidConfigurationException(sprintf(
                    'medzuch_jwt.jwks publishes key "%s", which has no public half to publish.',
                    $name,
                ));
            }
        }

        self::assertNamesAreUnique('medzuch_jwt.jwks', $jwks['keys']);
        $this->assertKeysAreDistinguishable('medzuch_jwt.jwks', array_intersect_key($keys, array_flip($jwks['keys'])));

        $services->set('medzuch_jwt.jwks.key_set', JwkSet::class)
            ->factory([JwkSet::class, 'of'])
            ->args(array_map(static fn(string $key): mixed => service('medzuch_jwt.key.' . $key . '.verification'), array_values($jwks['keys'])));

        $services->set('medzuch_jwt.jwks_controller', JwksController::class)
            ->args([service('medzuch_jwt.jwks.key_set'), $jwks['cache_max_age']])
            // Public is what makes `controller: medzuch_jwt.jwks_controller`
            // resolvable. No `controller.service_arguments` tag: the action
            // takes a Request, which the standard resolver provides, and no
            // services at all.
            ->public();
    }

    /**
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                                              $keys
     * @param array<string, array{issuer: string, audience: list<string>, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}> $consumers
     * @param array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>      $sets
     */
    private function registerConsumers(ServicesConfigurator $services, array $keys, array $consumers, array $sets, ?string $logger): void
    {
        foreach ($consumers as $name => $consumer) {
            $this->assertCanVerify(sprintf('Consumer "%s"', $name), $consumer, $keys, $sets);

            self::registerLocalKeySet($services, 'medzuch_jwt.jwk_set.' . $name, $consumer);

            $services->set('medzuch_jwt.consumer.' . $name, AccessTokenConsumer::class)
                ->factory([AccessTokenProfile::class, 'consumer'])
                ->args([
                    $consumer['issuer'],
                    array_values($consumer['audience']),
                    self::keySource($services, 'medzuch_jwt.jwk_set.' . $name, 'medzuch_jwt.resolver.' . $name, $consumer),
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
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                              $keys
     * @param array<string, array{issuer: string, client_id: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, leeway: int}>                                                                                                                                         $registrations
     * @param array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>                                                                                                     $sets
     */
    private function registerIdTokens(ServicesConfigurator $services, ContainerBuilder $builder, array $keys, array $registrations, array $sets, ?string $logger): void
    {
        foreach ($registrations as $name => $registration) {
            $this->assertCanVerify(sprintf('ID token registration "%s"', $name), $registration, $keys, $sets);

            $id = 'medzuch_jwt.id_token.' . $name;
            self::registerLocalKeySet($services, $id . '.jwk_set', $registration);

            $services->set($id, IdTokenVerifier::class)
                ->args([
                    $registration['issuer'],
                    $registration['client_id'],
                    self::keySource($services, $id . '.jwk_set', $id . '.resolver', $registration),
                    array_map(static fn(string $alg): mixed => inline_service(SigningAlgorithms::CLASSES[$alg]), array_values($registration['allowed_algorithms'])),
                    service('medzuch_jwt.clock'),
                    null === $logger ? null : service($logger),
                    0 === $registration['leeway'] ? null : inline_service(DateInterval::class)->args([sprintf('PT%dS', $registration['leeway'])]),
                ])
                // Public because the application calls it directly, from its
                // OIDC callback: there is no firewall to inject it into.
                ->public();

            // …and injectable by name, so a controller can ask for
            // `IdTokenVerifier $partner` and get the registration called
            // "partner" rather than a container lookup by string.
            $builder->registerAliasForArgument($id, IdTokenVerifier::class, $name);
        }
    }

    /**
     * What the consumer verifies against: the local set, the remote one, or
     * both — and when both, the local one first, so a key already configured
     * is never a network round trip, and an issuer outage cannot stop tokens
     * signed with keys this application already holds (K6).
     *
     * A composite is only worth building when there is something to compose:
     * with one source the resolver is that source, and the set goes to the
     * profile as a set, which is what it does when no remote is configured at
     * all.
     *
     * @param array{keys: list<string>, remote_jwks: string|null, ...} $entry
     */
    private static function keySource(ServicesConfigurator $services, string $setId, string $resolverId, array $entry): mixed
    {
        if (null === $entry['remote_jwks']) {
            return service($setId);
        }

        $remote = service('medzuch_jwt.remote_jwks.' . $entry['remote_jwks']);

        if ([] === $entry['keys']) {
            return $remote;
        }

        $services->set($resolverId, CompositeResolver::class)
            ->args([
                inline_service(StaticJwkSetResolver::class)->args([service($setId)]),
                $remote,
            ]);

        return service($resolverId);
    }

    /**
     * The local half of a verification set, registered only when there is one:
     * an entry verifying against a remote set alone would otherwise leave a
     * service nothing references, showing up in `debug:container` as a key set
     * with no keys in it.
     *
     * @param array{keys: list<string>, ...}                                                                                                                                                                 $entry
     */
    private static function registerLocalKeySet(ServicesConfigurator $services, string $setId, array $entry): void
    {
        if ([] === $entry['keys']) {
            return;
        }

        $services->set($setId, JwkSet::class)
            ->factory([JwkSet::class, 'of'])
            ->args(array_map(static fn(string $key): mixed => service('medzuch_jwt.key.' . $key . '.verification'), array_values($entry['keys'])));
    }

    /**
     * @param array{keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, ...}                                                                                                                                                                                              $consumer
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                              $keys
     * @param array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>                                                                                                     $sets
     */
    private function assertCanVerify(string $context, array $consumer, array $keys, array $sets): void
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

            if (!self::hasPublicHalf($keys[$key])) {
                throw new InvalidConfigurationException(sprintf(
                    '%s verifies with key "%s", which has only a private half. Verification needs the public one — a private key cannot stand in for it.',
                    $context,
                    $key,
                ));
            }

            $bound[] = $keys[$key]['algorithm'];
        }

        self::assertNamesAreUnique($context, $consumer['keys']);
        $this->assertKeysAreDistinguishable($context, array_intersect_key($keys, array_flip($consumer['keys'])));

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
