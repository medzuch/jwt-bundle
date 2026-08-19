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
         *     keys: array<string, array{hmac: string, algorithm: string, kid: string|null}>,
         *     issuers: array<string, array{issuer: string, key: string, client_id: string, ttl: int, audience: list<string>, claims: array<string, mixed>}>,
         *     consumers: array<string, array{issuer: string, audience: list<string>, keys: list<string>, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}>,
         * } $config */
        $container->import('../config/services.php');

        if (null !== $config['clock']) {
            // setAlias() drops the definition from services.php, so the
            // container holds exactly one medzuch_jwt.clock either way.
            $builder->setAlias('medzuch_jwt.clock', $config['clock']);
        }

        $this->assertKeysAreDistinguishable($config['keys']);

        $services = $container->services();
        $this->registerKeys($services, $config['keys']);
        $this->registerIssuers($services, $config['keys'], $config['issuers']);
        $this->registerConsumers($services, $config['keys'], $config['consumers'], $config['logger']);
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

        $key->scalarNode('hmac')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Shared secret, at least 32/48/64 bytes for HS256/384/512 (RFC 8725 §3.5). Use an env reference; %env(base64:NAME)% decodes a base64 secret. The length cannot be checked at build: the secret stays an env reference so it never reaches a container parameter, so a short one fails when the key is first used.')
            ->example('%env(JWT_SECRET)%')
            ->end();

        $key->enumNode('algorithm')
            ->values(SigningAlgorithms::HMAC)
            ->defaultValue('HS256')
            ->info('The algorithm this key is bound to. A key verifies nothing else.')
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
     * token still in flight (DEC-5). Both are refused here rather than
     * discovered mid-rotation.
     *
     * @param array<string, array{hmac: string, algorithm: string, kid: string|null}> $keys
     */
    private function assertKeysAreDistinguishable(array $keys): void
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
                    'Keys "%s" are all bound to %s with no "kid", so a token cannot say which one signed it. Give each of them a kid.',
                    implode('", "', $names),
                    $algorithm,
                ));
            }
        }

        foreach ($namesByKid as $kid => $names) {
            if (count($names) > 1) {
                throw new InvalidConfigurationException(sprintf(
                    'Keys "%s" share the kid "%s". A token naming it is verified against the first of them and never the others.',
                    implode('", "', $names),
                    $kid,
                ));
            }
        }
    }

    /**
     * @param array<string, array{hmac: string, algorithm: string, kid: string|null}> $keys
     */
    private function registerKeys(ServicesConfigurator $services, array $keys): void
    {
        foreach ($keys as $name => $key) {
            // The secret stays an env reference all the way into the factory
            // argument: resolved as a container parameter it would show up in
            // `debug:container` output (K9).
            $services->set('medzuch_jwt.key.' . $name, HmacKey::class)
                ->factory([HmacKey::class, 'fromBinary'])
                ->args([$key['hmac'], $key['algorithm'], $key['kid']]);
        }
    }

    /**
     * @param array<string, array{hmac: string, algorithm: string, kid: string|null}>                                                                    $keys
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

            $services->set('medzuch_jwt.profile.' . $name, AccessTokenProfile::class)
                ->factory([AccessTokenProfile::class, 'issuer'])
                ->args([
                    $issuer['issuer'],
                    inline_service(SigningAlgorithms::CLASSES[$keys[$issuer['key']]['algorithm']]),
                    service('medzuch_jwt.key.' . $issuer['key']),
                    service('medzuch_jwt.clock'),
                ]);

            $services->set('medzuch_jwt.issuer.' . $name, AccessTokenIssuer::class)
                ->args([
                    service('medzuch_jwt.profile.' . $name),
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
     * @param array<string, array{hmac: string, algorithm: string, kid: string|null}>                                                                                              $keys
     * @param array<string, array{issuer: string, audience: list<string>, keys: list<string>, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}> $consumers
     */
    private function registerConsumers(ServicesConfigurator $services, array $keys, array $consumers, ?string $logger): void
    {
        foreach ($consumers as $name => $consumer) {
            $this->assertConsumerCanVerify($name, $consumer, $keys);

            $services->set('medzuch_jwt.jwk_set.' . $name, JwkSet::class)
                ->factory([JwkSet::class, 'of'])
                ->args(array_map(static fn(string $key): mixed => service('medzuch_jwt.key.' . $key), array_values($consumer['keys'])));

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
     * @param array<string, array{hmac: string, algorithm: string, kid: string|null}>                                                                              $keys
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

            $bound[] = $keys[$key]['algorithm'];
        }

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
