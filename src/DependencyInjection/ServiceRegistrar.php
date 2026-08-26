<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\DependencyInjection;

use DateInterval;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Jwt\Validator;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\CompositeResolver;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Profile\AccessTokenConsumer;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Medzuch\JwtBundle\DataCollector\JwtDataCollector;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Issuer\TokenClaimProviderInterface;
use Medzuch\JwtBundle\Jwks\JwksController;
use Medzuch\JwtBundle\Key\KeyLoader;
use Medzuch\JwtBundle\Oidc\IdTokenVerifier;
use Medzuch\JwtBundle\Revocation\CacheTokenDenylist;
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\AccessTokenSuccessHandler;
use Medzuch\JwtBundle\Security\Authorization\ScopeExpressionProvider;
use Medzuch\JwtBundle\Security\Authorization\ScopeVoter;
use Medzuch\JwtBundle\Security\Extractor\CookieTokenExtractor;
use Medzuch\JwtBundle\Security\Http\BearerEntryPoint;
use Medzuch\JwtBundle\Security\Http\InsufficientScopeHandler;
use Medzuch\JwtBundle\Security\Identity\ClaimsUserResolver;
use Medzuch\JwtBundle\Security\Identity\CustomUserResolver;
use Medzuch\JwtBundle\Security\Identity\ProviderUserResolver;
use Medzuch\JwtBundle\Security\User\ClaimRoles;
use Medzuch\JwtBundle\Security\User\JwtUserFactoryInterface;
use Medzuch\JwtBundle\Security\Verification\CustomTokenVerifier;
use Medzuch\JwtBundle\Security\Verification\CustomValidatorFactory;
use Medzuch\JwtBundle\Security\Verification\ProfileTokenVerifier;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\InlineServiceConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use Symfony\Component\ExpressionLanguage\ExpressionFunction;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/**
 * Turns a validated `medzuch_jwt` tree into service definitions.
 *
 * Its own class rather than the bundle's body: this is where every feature adds
 * a registration, so this is where the merge conflicts are.
 *
 * Holds the {@see ConfiguredServices} bag the bundle also hands to
 * {@see CheckConfiguredServicesPass} — filled here while the extension runs,
 * read by the pass once every other extension has run.
 *
 * @internal
 */
final class ServiceRegistrar
{
    public function __construct(private readonly ConfiguredServices $configured) {}

    /**
     * The shape below is what {@see ConfigurationTree} guarantees; `$config`
     * arrives untyped because the bundle's `loadExtension()` signature, which
     * Symfony fixes, says `array`.
     *
     * @param array<array-key, mixed> $config
     */
    public function register(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        /** @var array{
         *     clock: string|null,
         *     logger: string|null,
         *     log_levels: array<string, string|null>,
         *     keys: array<string, array{hmac?: string, pem_private?: string, pem_public?: string, jwk_private?: string, jwk_public?: string, pem_passphrase?: string, algorithm: string, kid: string|null}>,
         *     issuers: array<string, array{issuer: string, key: string, client_id: string, ttl: int, audience: list<string>, claims: array<string, mixed>}>,
         *     jwks: array{keys: list<string>, cache_max_age: int},
         *     remote_jwks: array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>,
         *     consumers: array<string, array{issuer: string, audience: list<string>, audience_policy: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, realm: string|null, leeway: int, token_type: string|null, required_claims: list<string>, max_token_age: int|null, denylist: array{service: string|null, cache_pool: string|null, cache: string|null, prefix: string}, user: array{mode: string, identity_claim: string, factory: string|null, roles: array{claim: string|null, separator: string|null, prefix: string, defaults: list<string>}}}>,
         *     id_tokens: array<string, array{issuer: string, client_id: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, leeway: int}>,
         *     token_extractors: array<string, array{cookie: string, same_site_only: bool}>,
         * } $config */
        // Relative to the *bundle*, not to this file: Symfony anchors the
        // configurator on `new ReflectionObject($bundle)->getFileName()`, so
        // the path is one level up from `src/MedzuchJwtBundle.php` wherever
        // the call is written.
        $container->import('../config/services.yaml');

        if (null !== $config['clock']) {
            // setAlias() drops the definition from services.php, so the
            // container holds exactly one medzuch_jwt.clock either way.
            $builder->setAlias('medzuch_jwt.clock', $config['clock']);
        }

        $this->configured->record(self::configuredServices($config));

        // Levels with nothing to log them are a setting nothing reads, the same
        // as a `factory` outside `user.mode: custom` or `required_claims`
        // without a `token_type`.
        if (null === $config['logger'] && self::hasLevels($config['log_levels'])) {
            throw new InvalidConfigurationException('medzuch_jwt.log_levels is set and medzuch_jwt.logger is not, so nothing would emit at those levels. Name a PSR-3 service under "logger", or drop the levels.');
        }

        $keys = KeyEntries::of($config['keys']);

        // Implementing the interface is the whole registration: a claim
        // provider is application code, and asking it to also remember a tag
        // would make a silent no-op the price of forgetting.
        $builder->registerForAutoconfiguration(TokenClaimProviderInterface::class)
            ->addTag('medzuch_jwt.token_claim_provider');

        $services = $container->services();
        $this->registerKeys($services, $keys);
        $this->registerRemoteJwks($services, $builder, $config['remote_jwks'], $config['logger'], $config['log_levels']);
        $this->registerIssuers($services, $keys, $config['issuers']);
        $this->registerConsumers($services, $builder, $keys, $config['consumers'], $config['remote_jwks'], $config['logger'], $config['log_levels']);
        $this->registerTokenExtractors($services, $config['token_extractors']);
        $this->registerIdTokens($services, $builder, $keys, $config['id_tokens'], $config['remote_jwks'], $config['logger'], $config['log_levels']);

        ConsoleCommands::register(
            $services,
            $config,
            $keys,
            $this->registerJwks($services, $keys, $config['jwks']),
        );
        $this->registerAuthorization($services);

        // Registered unconditionally and removed by the pass where no profiler
        // wants it: a data collector is one definition, and deciding here would
        // mean guessing at an extension that may not have run yet.
        $services->set('medzuch_jwt.data_collector', JwtDataCollector::class)
            ->tag('data_collector', [
                'id' => 'medzuch_jwt',
                'template' => '@MedzuchJwt/data_collector/jwt.html.twig',
                'priority' => 300,
            ]);
    }

    /**
     * Every service id the configuration names, keyed by the path that named
     * it, for {@see CheckConfiguredServicesPass} to check once every extension
     * has run.
     *
     * The defaults are in here too, and they are the entries that most need a
     * hint: `psr18.http_client` and `cache.app` are ids this bundle chose, so
     * an application missing one has written nothing wrong — it has enabled
     * neither the client nor the cache the default assumes.
     *
     * Only one of those two hints fires in practice. `psr18.http_client` exists
     * where `psr/http-client` is installed and `framework.http_client` is
     * enabled, which is a real thing to forget; `cache.app` is registered by
     * FrameworkBundle unconditionally, so its hint is for a container that has
     * no FrameworkBundle at all. The entry stays either way — an id this bundle
     * chose is still an id it should not assume.
     *
     * @param array{
     *     clock: string|null,
     *     logger: string|null,
     *     remote_jwks: array<string, array{http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, ...}>,
     *     consumers: array<string, array{denylist: array{service: string|null, cache_pool: string|null, cache: string|null, ...}, user: array{factory: string|null, ...}, ...}>,
     *     ...
     * } $config
     *
     * @return array<string, array{id: string, hint: string|null}>
     */
    private static function configuredServices(array $config): array
    {
        $named = [];

        foreach (['clock', 'logger'] as $option) {
            if (null !== $config[$option]) {
                $named['medzuch_jwt.' . $option] = ['id' => $config[$option], 'hint' => null];
            }
        }

        foreach ($config['remote_jwks'] as $name => $set) {
            $path = sprintf('medzuch_jwt.remote_jwks.%s', $name);

            $named[$path . '.http_client'] = [
                'id' => $set['http_client'],
                'hint' => 'psr18.http_client' === $set['http_client']
                    ? 'the default. Install `psr/http-client` and enable `framework.http_client`, or name a PSR-18 client of your own'
                    : null,
            ];

            if (null !== $set['request_factory']) {
                $named[$path . '.request_factory'] = ['id' => $set['request_factory'], 'hint' => null];
            }

            if (null !== $set['cache']) {
                $named[$path . '.cache'] = ['id' => $set['cache'], 'hint' => null];

                continue;
            }

            $named[$path . '.cache_pool'] = [
                'id' => $set['cache_pool'] ?? 'cache.app',
                'hint' => null === $set['cache_pool']
                    ? 'the default. Enable `framework.cache`, or name a pool or a PSR-16 `cache` of your own'
                    : null,
            ];
        }

        foreach ($config['consumers'] as $name => $consumer) {
            $path = sprintf('medzuch_jwt.consumers.%s', $name);

            // No default among these three, unlike a remote set's cache: a
            // consumer that names none of them gets no denylist at all, so
            // there is no id this bundle chose on its behalf to check.
            foreach (['service', 'cache_pool', 'cache'] as $option) {
                if (null !== $consumer['denylist'][$option]) {
                    $named[$path . '.denylist.' . $option] = ['id' => $consumer['denylist'][$option], 'hint' => null];
                }
            }

            if (null !== $consumer['user']['factory']) {
                $named[$path . '.user.factory'] = [
                    'id' => $consumer['user']['factory'],
                    'hint' => 'a service implementing ' . JwtUserFactoryInterface::class,
                ];
            }
        }

        return $named;
    }

    /**
     * The voter is registered unconditionally: it answers only `SCOPE_*`, and
     * an application with no scopes in its tokens simply never asks. Under the
     * default affirmative strategy its denial cannot override another voter's
     * grant, so there is nothing here to switch off — under `unanimous` or
     * `consensus` it votes like any other voter, which is what those strategies
     * are for.
     *
     * The expression function is another matter — `symfony/expression-language`
     * is optional, and a provider registered where Symfony has dropped the
     * expression language is a tag nobody collects. `willBeAvailable()` is the
     * same question SecurityBundle asks before removing it, rather than
     * `class_exists()`, which answers a narrower one.
     */
    private function registerAuthorization(ServicesConfigurator $services): void
    {
        $services->set('medzuch_jwt.scope_voter', ScopeVoter::class)
            ->tag('security.voter');

        if (!ContainerBuilder::willBeAvailable('symfony/expression-language', ExpressionFunction::class, ['medzuch/jwt-bundle'])) {
            return;
        }

        $services->set('medzuch_jwt.scope_expression_provider', ScopeExpressionProvider::class)
            ->tag('security.expression_language_provider');
    }

    /**
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}> $keys
     */
    private function registerKeys(ServicesConfigurator $services, array $keys): void
    {
        foreach ($keys as $name => $key) {
            ConfigurationGuard::assertKeyMaterialMatchesAlgorithm($name, $key);

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
     * @param array<string, string|null> $logLevels
     */
    private function registerRemoteJwks(ServicesConfigurator $services, ContainerBuilder $builder, array $sets, ?string $logger, array $logLevels): void
    {
        foreach ($sets as $name => $set) {
            ConfigurationGuard::assertRemoteJwksIsUsable($name, $set, $builder);

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
                    self::logLevels($logLevels),
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

            if (!KeyEntries::hasPrivateHalf($keys[$issuer['key']])) {
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
                    $name,
                    array_values($issuer['audience']),
                    $issuer['client_id'],
                    $issuer['ttl'],
                    $issuer['claims'],
                    tagged_iterator('medzuch_jwt.token_claim_provider'),
                    // Optional so the issuer stands on its own: outside a
                    // Symfony application — a unit test, a script — there is no
                    // dispatcher, and issuance is not the place to require one.
                    service('event_dispatcher')->nullOnInvalid(),
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
     *
     * @return bool whether there is a set to serve, which is also the answer to
     *              whether there is one to dump — returned rather than asked
     *              again, so the command cannot be registered against a key set
     *              this method decided not to build
     */
    private function registerJwks(ServicesConfigurator $services, array $keys, array $jwks): bool
    {
        if ([] === $jwks['keys']) {
            return false;
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

            if (!KeyEntries::hasPublicHalf($keys[$name])) {
                throw new InvalidConfigurationException(sprintf(
                    'medzuch_jwt.jwks publishes key "%s", which has no public half to publish.',
                    $name,
                ));
            }
        }

        ConfigurationGuard::assertNamesAreUnique('medzuch_jwt.jwks', $jwks['keys']);
        ConfigurationGuard::assertKeysAreDistinguishable('medzuch_jwt.jwks', array_intersect_key($keys, array_flip($jwks['keys'])));

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

        return true;
    }

    /**
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                                              $keys
     * @param array<string, array{issuer: string, audience: list<string>, audience_policy: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, realm: string|null, leeway: int, token_type: string|null, required_claims: list<string>, max_token_age: int|null, denylist: array{service: string|null, cache_pool: string|null, cache: string|null, prefix: string}, user: array{mode: string, identity_claim: string, factory: string|null, roles: array{claim: string|null, separator: string|null, prefix: string, defaults: list<string>}}}> $consumers
     * @param array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>      $sets
     * @param array<string, string|null> $logLevels
     */
    private function registerConsumers(ServicesConfigurator $services, ContainerBuilder $builder, array $keys, array $consumers, array $sets, ?string $logger, array $logLevels): void
    {
        foreach ($consumers as $name => $consumer) {
            ConfigurationGuard::assertCanVerify(sprintf('Consumer "%s"', $name), $consumer, $keys, $sets);

            self::registerLocalKeySet($services, 'medzuch_jwt.jwk_set.' . $name, $consumer);

            ConfigurationGuard::assertTokenTypeIsUsable($name, $consumer);

            $keySource = self::keySource($services, 'medzuch_jwt.jwk_set.' . $name, 'medzuch_jwt.resolver.' . $name, $consumer);
            $algorithms = array_map(static fn(string $alg): mixed => inline_service(SigningAlgorithms::CLASSES[$alg]), array_values($consumer['allowed_algorithms']));
            $leeway = 0 === $consumer['leeway'] ? null : inline_service(DateInterval::class)->args([sprintf('PT%dS', $consumer['leeway'])]);

            if (null === $consumer['token_type']) {
                $services->set('medzuch_jwt.consumer.' . $name, AccessTokenConsumer::class)
                    ->factory([AccessTokenProfile::class, 'consumer'])
                    ->args([
                        $consumer['issuer'],
                        array_values($consumer['audience']),
                        $keySource,
                        $algorithms,
                        service('medzuch_jwt.clock'),
                        null === $logger ? null : service($logger),
                        self::logLevels($logLevels),
                        $leeway,
                    ]);

                $services->set('medzuch_jwt.verifier.' . $name, ProfileTokenVerifier::class)
                    ->args([service('medzuch_jwt.consumer.' . $name)]);
            } else {
                // The lower-level API, which `04-api-surface.md` calls the one
                // for custom flows and freezes as public. There is no fourth
                // profile to build this from: a `typ` only this application
                // knows has no posture to standardise, and the library's own
                // consumer constructors are `@internal`.
                $services->set('medzuch_jwt.consumer.' . $name, Validator::class)
                    ->factory([CustomValidatorFactory::class, 'forTokenType'])
                    ->args([
                        $consumer['token_type'],
                        $consumer['issuer'],
                        array_values($consumer['audience']),
                        $keySource,
                        $algorithms,
                        [] === $consumer['required_claims'] ? ConfigurationGuard::DEFAULT_REQUIRED_CLAIMS : array_values($consumer['required_claims']),
                        service('medzuch_jwt.clock'),
                        null === $logger ? null : service($logger),
                        self::logLevels($logLevels),
                        $leeway,
                    ]);

                $services->set('medzuch_jwt.verifier.' . $name, CustomTokenVerifier::class)
                    ->args([service('medzuch_jwt.consumer.' . $name)]);
            }

            // The two answers RFC 6750 asks for that Symfony has none of: the
            // challenge for a request carrying no credentials, and the 403 that
            // names the scope which would have been enough. Both are the
            // application's to wire into its firewall, like every other service
            // here — a bundle that reached into `security.yaml` would be
            // deciding which firewall this consumer belongs to (DEC-1).
            $realm = $consumer['realm'] ?? $name;

            $services->set('medzuch_jwt.entry_point.' . $name, BearerEntryPoint::class)
                ->args([$realm]);

            $services->set('medzuch_jwt.access_denied.' . $name, InsufficientScopeHandler::class)
                ->args([$realm]);

            $services->set('medzuch_jwt.handler.' . $name, AccessTokenHandler::class)
                // Tagged so the profiler pass can find every handler without
                // knowing how consumers are named, and carrying the name it
                // would otherwise have to parse back out of the service id.
                ->tag('medzuch_jwt.token_handler', ['consumer' => $name])
                ->args([
                    service('medzuch_jwt.verifier.' . $name),
                    $name,
                    self::userResolver($name, $consumer['user']),
                    service('medzuch_jwt.clock'),
                    'exclusive' === $consumer['audience_policy'] ? array_values($consumer['audience']) : null,
                    $consumer['max_token_age'],
                    $consumer['leeway'],
                    self::registerDenylist($services, $builder, $name, $consumer['denylist'], $consumer['leeway']),
                    service('event_dispatcher')->nullOnInvalid(),
                ]);
        }
    }

    /**
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                              $keys
     * @param array<string, array{issuer: string, client_id: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, leeway: int}>                                                                                                                                         $registrations
     * @param array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>                                                                                                     $sets
     * @param array<string, string|null> $logLevels
     */
    private function registerIdTokens(ServicesConfigurator $services, ContainerBuilder $builder, array $keys, array $registrations, array $sets, ?string $logger, array $logLevels): void
    {
        foreach ($registrations as $name => $registration) {
            ConfigurationGuard::assertCanVerify(sprintf('ID token registration "%s"', $name), $registration, $keys, $sets);

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
                    self::logLevels($logLevels),
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
     * @param array<string, array{cookie: string, same_site_only: bool}> $extractors
     */
    private function registerTokenExtractors(ServicesConfigurator $services, array $extractors): void
    {
        foreach ($extractors as $name => $extractor) {
            $services->set('medzuch_jwt.token_extractor.' . $name, CookieTokenExtractor::class)
                ->args([$extractor['cookie'], $extractor['same_site_only']]);
        }
    }

    /**
     * The denylist this consumer asks, or nothing at all.
     *
     * Nothing, rather than a null object that always answers "not revoked":
     * the check is one branch either way, and a service in the container would
     * say revocation is configured when it is not — `debug:container` would
     * show a denylist to an application that never asked for one (DEC-3 called
     * for a NullDenylist; this is the same default said with less).
     *
     * @param array{service: string|null, cache_pool: string|null, cache: string|null, prefix: string} $denylist
     */
    private static function registerDenylist(ServicesConfigurator $services, ContainerBuilder $builder, string $name, array $denylist, int $leeway): ?ReferenceConfigurator
    {
        $named = array_filter([
            'service' => $denylist['service'],
            'cache_pool' => $denylist['cache_pool'],
            'cache' => $denylist['cache'],
        ], static fn(?string $id): bool => null !== $id);

        if (count($named) > 1) {
            throw new InvalidConfigurationException(sprintf('Consumer "%s" gives its denylist %s. Give one: a service of your own, or a cache for the one this bundle ships.', $name, '"' . implode('" and "', array_keys($named)) . '"'));
        }

        if ([] === $named) {
            return null;
        }

        $id = 'medzuch_jwt.denylist.' . $name;

        // A named service, not an argument built in place: revocation is only
        // half a feature if nothing can revoke. The application needs to reach
        // this from a logout controller, so it is public and injectable by
        // argument name, exactly like the consumer it belongs to.
        if (null !== $denylist['service']) {
            // A prefix beside a service of your own is a setting nothing will
            // read: the prefix belongs to the cache implementation this bundle
            // ships, and yours keys its own store however it likes.
            if (ConfigurationTree::DEFAULT_DENYLIST_PREFIX !== $denylist['prefix']) {
                throw new InvalidConfigurationException(sprintf('Consumer "%s" sets a denylist "prefix" beside its own "service". The prefix belongs to the cache this bundle ships; a service of yours keys its store itself.', $name));
            }

            $services->alias($id, $denylist['service'])->public();
        } else {
            $services->set($id, CacheTokenDenylist::class)
                ->args([
                    null !== $denylist['cache']
                        ? service($denylist['cache'])
                        : inline_service(Psr16Cache::class)->args([service((string) $denylist['cache_pool'])]),
                    service('medzuch_jwt.clock'),
                    $denylist['prefix'],
                    $leeway,
                ])
                ->public();
        }

        $builder->registerAliasForArgument($id, TokenDenylistInterface::class, $name);

        return service($id);
    }

    /**
     * Which of the three answers to "who is this token about" this consumer
     * gives, as one collaborator rather than a handful of nullable arguments
     * the handler would have to interpret.
     *
     * @param array{mode: string, identity_claim: string, factory: string|null, roles: array{claim: string|null, separator: string|null, prefix: string, defaults: list<string>}} $user
     */
    private static function userResolver(string $name, array $user): InlineServiceConfigurator
    {
        ConfigurationGuard::assertUserModeIsCoherent($name, $user);

        return match ($user['mode']) {
            'claims' => inline_service(ClaimsUserResolver::class)->args([
                $user['identity_claim'],
                inline_service(ClaimRoles::class)->args([
                    $user['roles']['claim'],
                    $user['roles']['separator'],
                    $user['roles']['prefix'],
                    array_values($user['roles']['defaults']),
                ]),
            ]),
            'custom' => inline_service(CustomUserResolver::class)->args([service((string) $user['factory'])]),
            default => inline_service(ProviderUserResolver::class)->args([$user['identity_claim']]),
        };
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
     * The levels service, or null where every category was left alone.
     *
     * Named arguments rather than positional, so the two JWE categories this
     * bundle has no option for keep the library's defaults instead of being
     * restated here — a copy of somebody else's default is a copy that goes
     * stale. A fresh definition per call site, because a `Definition` handed to
     * two services is one object in two places.
     *
     * @param array<string, string|null> $levels
     */
    private static function logLevels(array $levels): ?InlineServiceConfigurator
    {
        if (!self::hasLevels($levels)) {
            return null;
        }

        $service = inline_service(LogLevels::class);

        foreach ($levels as $option => $level) {
            if (null !== $level) {
                $service = $service->arg('$' . ConfigurationTree::LOG_LEVELS[$option][0], $level);
            }
        }

        return $service;
    }

    /**
     * Whether any category was written at all.
     *
     * One rule in one place: the build-time refusal of levels without a logger
     * and the early return here have to agree, or {@see logLevels()} could
     * return a service on a configuration the refusal let past.
     *
     * @param array<string, string|null> $levels
     */
    private static function hasLevels(array $levels): bool
    {
        return [] !== array_filter($levels, static fn(?string $level): bool => null !== $level);
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
}
