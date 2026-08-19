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
use Medzuch\JwtBundle\Security\AccessTokenHandler;
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
         *     consumers: array<string, array{issuer: string, audience: list<string>, keys: list<string>, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}>,
         * } $config */
        $container->import('../config/services.php');

        if (null !== $config['clock']) {
            // setAlias() drops the definition from services.php, so the
            // container holds exactly one medzuch_jwt.clock either way.
            $builder->setAlias('medzuch_jwt.clock', $config['clock']);
        }

        $this->assertKidsAreDistinguishable($config['keys']);

        $services = $container->services();
        $this->registerKeys($services, $config['keys']);
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
            ->info('Shared secret. Use an env reference; %env(base64:NAME)% decodes a base64 secret.')
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

        $keys = $consumer->arrayNode('keys');
        $keys->info('Names from the `keys` section. Verification tries the key the token names, or the one bound to its algorithm.');
        $keys->scalarPrototype()->cannotBeEmpty()->end();
        $keys->isRequired();
        $keys->requiresAtLeastOneElement();

        $algorithms = $consumer->arrayNode('allowed_algorithms');
        $algorithms->info('JOSE `alg` values accepted. Anything else is refused before a signature is checked.');
        $algorithms->enumPrototype()->values(SigningAlgorithms::names())->end();
        $algorithms->isRequired();
        $algorithms->requiresAtLeastOneElement();

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
     * DEC-5: without a `kid`, the library resolves a token to the *first* key
     * bound to its algorithm and fails if that one does not verify — it does not
     * try the rest. Two kid-less keys on one algorithm therefore make rotation a
     * hard cutover that invalidates every token in flight, which is worth
     * refusing at build rather than discovering mid-rotation.
     *
     * @param array<string, array{hmac: string, algorithm: string, kid: string|null}> $keys
     */
    private function assertKidsAreDistinguishable(array $keys): void
    {
        $anonymousByAlgorithm = [];

        foreach ($keys as $name => $key) {
            if (null === $key['kid']) {
                $anonymousByAlgorithm[$key['algorithm']][] = $name;
            }
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
     * @param array<string, array{hmac: string, algorithm: string, kid: string|null}>                                                                                              $keys
     * @param array<string, array{issuer: string, audience: list<string>, keys: list<string>, allowed_algorithms: list<string>, leeway: int, user: array{identity_claim: string}}> $consumers
     */
    private function registerConsumers(ServicesConfigurator $services, array $keys, array $consumers, ?string $logger): void
    {
        foreach ($consumers as $name => $consumer) {
            $this->assertConsumerCanVerify($name, $consumer, $keys);

            $services->set('medzuch_jwt.jwk_set.' . $name, JwkSet::class)
                ->factory([JwkSet::class, 'of'])
                ->args(array_map(static fn(string $key): mixed => service('medzuch_jwt.key.' . $key), $consumer['keys']));

            $services->set('medzuch_jwt.consumer.' . $name, AccessTokenConsumer::class)
                ->factory([AccessTokenProfile::class, 'consumer'])
                ->args([
                    $consumer['issuer'],
                    $consumer['audience'],
                    service('medzuch_jwt.jwk_set.' . $name),
                    array_map(static fn(string $alg): mixed => inline_service(SigningAlgorithms::CLASSES[$alg]), $consumer['allowed_algorithms']),
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

        // A consumer whose keys are bound to none of its allowed algorithms
        // rejects every token it will ever see. That is a wiring mistake, and
        // it is knowable now rather than at the first request.
        if ([] === array_intersect($bound, $consumer['allowed_algorithms'])) {
            throw new InvalidConfigurationException(sprintf(
                'Consumer "%s" allows %s but its keys are bound to %s, so it can never verify a token.',
                $name,
                implode('/', $consumer['allowed_algorithms']),
                implode('/', array_unique($bound)),
            ));
        }
    }
}
