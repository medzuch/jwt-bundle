<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle;

use DateInterval;
use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Jwt\MediaType;
use Medzuch\Jwt\Jwt\Validator;
use Medzuch\Jwt\Jwt\ValidatorBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\CompositeResolver;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Key\Resolver\StaticJwkSetResolver;
use Medzuch\Jwt\Profile\AccessTokenConsumer;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Algorithm\SigningAlgorithms;
use Medzuch\JwtBundle\Command\CheckConfigurationCommand;
use Medzuch\JwtBundle\Command\CreateTokenCommand;
use Medzuch\JwtBundle\Command\DumpJwksCommand;
use Medzuch\JwtBundle\Command\GenerateKeyCommand;
use Medzuch\JwtBundle\Command\InspectTokenCommand;
use Medzuch\JwtBundle\DataCollector\CollectVerdictsPass;
use Medzuch\JwtBundle\DataCollector\JwtDataCollector;
use Medzuch\JwtBundle\DependencyInjection\CheckConfiguredServicesPass;
use Medzuch\JwtBundle\DependencyInjection\ConfiguredServices;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Issuer\ReservedClaims;
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
use Medzuch\JwtBundle\Security\Http\Challenge;
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
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\InlineServiceConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ServicesConfigurator;
use Symfony\Component\ExpressionLanguage\ExpressionFunction;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_closure;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_locator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

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
    /** Named because the registration compares against it to catch a prefix nothing would read. */
    /**
     * Claims a custom consumer requires unless it says otherwise.
     *
     * `exp` and nothing else. The library checks `exp`, `nbf` and `iat` only
     * where the token carries them, so a custom posture that required nothing
     * would accept a credential with no expiry at all — one that lives until
     * somebody rotates a key. The profiles all require more than this; they can,
     * because they know what their tokens are for.
     */
    /**
     * The diagnostics this bundle can emit, as a configuration option, the
     * constructor argument it sets on {@see LogLevels}, and what it covers.
     *
     * Five of the library's seven. The other two are JWE — a token decrypted,
     * and one that would not decrypt — and nothing here issues or consumes an
     * encrypted token yet (C12/I8), so an option for them would be a level
     * nothing is ever emitted at.
     */
    private const LOG_LEVELS = [
        'accepted' => ['accepted', 'A token that passed every check. `debug` by default, because on a busy API this is one line per request.'],
        'verification_failed' => ['verificationFailed', 'Signature, algorithm allowlist, or key resolution while verifying — an integrity problem rather than a policy one. `warning` by default.'],
        'claim_rejected' => ['claimRejected', 'A properly signed token whose claims are refused: expired, not yet valid, wrong issuer or audience, a missing required claim, a profile rule. `notice` by default, because this is the ordinary cost of short lifetimes.'],
        'key_resolution' => ['keyResolution', 'A remote JWK Set fetched, served from cache, or refreshed. `debug` by default.'],
        'key_resolution_failed' => ['keyResolutionFailed', 'A remote JWK Set that could not be fetched or parsed — an outage on one side or the other. `warning` by default.'],
    ];

    private const DEFAULT_REQUIRED_CLAIMS = ['exp'];

    /**
     * Types the library has a profile for, which `token_type` must not name:
     * a consumer wanting one of these postures gets it by leaving the key out.
     */
    private const PROFILE_TOKEN_TYPES = [
        'at+jwt' => 'the RFC 9068 access-token profile, which a consumer uses by default',
        'JWT' => 'the generic RFC 7519 type',
    ];

    private const DEFAULT_DENYLIST_PREFIX = 'medzuch_jwt.revoked.';

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
        $this->configureTokenExtractors($children);
        $this->configureIdTokens($children);
        $this->configureJwks($children);
    }

    /**
     * Filled by {@see self::loadExtension()} and read by the pass
     * {@see self::build()} registers, which run at opposite ends of one
     * container build on this one object.
     */
    private readonly ConfiguredServices $configured;

    public function __construct()
    {
        $this->configured = new ConfiguredServices();
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        // After every extension, because whether there is a profiler to collect
        // for is another bundle's answer.
        $container->addCompilerPass(new CollectVerdictsPass());

        // Same reason, other subject, and later still: whether a service the
        // configuration names exists can be answered by another bundle's
        // *pass* rather than its extension — MonologBundle's `LoggerChannelPass`
        // is what creates `monolog.logger.jwt`, which this bundle's own
        // configuration reference recommends. TYPE_BEFORE_REMOVING is the last
        // point ahead of Symfony's own missing-service check, which is a
        // removing pass.
        $container->addCompilerPass(
            new CheckConfiguredServicesPass($this->configured),
            PassConfig::TYPE_BEFORE_REMOVING,
        );
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
         *     log_levels: array<string, string|null>,
         *     keys: array<string, array{hmac?: string, pem_private?: string, pem_public?: string, jwk_private?: string, jwk_public?: string, pem_passphrase?: string, algorithm: string, kid: string|null}>,
         *     issuers: array<string, array{issuer: string, key: string, client_id: string, ttl: int, audience: list<string>, claims: array<string, mixed>}>,
         *     jwks: array{keys: list<string>, cache_max_age: int},
         *     remote_jwks: array<string, array{uri: string, http_client: string, request_factory: string|null, cache_pool: string|null, cache: string|null, cache_ttl: int, min_refresh: int, max_body_bytes: int}>,
         *     consumers: array<string, array{issuer: string, audience: list<string>, audience_policy: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, realm: string|null, leeway: int, token_type: string|null, required_claims: list<string>, max_token_age: int|null, denylist: array{service: string|null, cache_pool: string|null, cache: string|null, prefix: string}, user: array{mode: string, identity_claim: string, factory: string|null, roles: array{claim: string|null, separator: string|null, prefix: string, defaults: list<string>}}}>,
         *     id_tokens: array<string, array{issuer: string, client_id: string, keys: list<string>, remote_jwks: string|null, allowed_algorithms: list<string>, leeway: int}>,
         *     token_extractors: array<string, array{cookie: string, same_site_only: bool}>,
         * } $config */
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
        if (null === $config['logger'] && [] !== array_filter($config['log_levels'], static fn(?string $level): bool => null !== $level)) {
            throw new InvalidConfigurationException('medzuch_jwt.log_levels is set and medzuch_jwt.logger is not, so nothing would emit at those levels. Name a PSR-3 service under "logger", or drop the levels.');
        }

        $keys = $this->keyEntries($config['keys']);

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

        $this->registerConsoleCommands(
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
     * The console is a dependency of applications, not of bundles: a worker
     * image that installs neither `symfony/console` nor a way to run it is a
     * normal way to deploy this bundle, and a service definition for a class
     * that cannot be loaded would break its container for a command it can
     * never run.
     *
     * The same reasoning one level down: `jwt:token:create` is registered only
     * where an issuer is, and `jwt:jwks:dump` only where there are keys to
     * publish, because a command whose every run ends in "nothing is
     * configured" is a line in `bin/console list` that promises something this
     * application cannot do. `jwt:token:inspect` is registered either way — it
     * decodes without configuration, which is exactly what a token from
     * somewhere else needs.
     *
     * The two that take a name reach their subjects through a service locator
     * rather than a container: the names are known at build time, and a command
     * that could fetch anything would be a command that can be asked for
     * anything.
     *
     * @param array{keys: array<string, mixed>, issuers: array<string, mixed>, consumers: array<string, mixed>, id_tokens: array<string, mixed>, remote_jwks: array<string, mixed>, ...} $config
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                                                              $keys
     * @param bool                                                                                                                                                                        $publishes whether a JWK Set service was registered to dump
     */
    private function registerConsoleCommands(ServicesConfigurator $services, array $config, array $keys, bool $publishes): void
    {
        if (!class_exists(Command::class)) {
            return;
        }

        $issuers = array_keys($config['issuers']);
        $consumers = array_keys($config['consumers']);

        $services->set('medzuch_jwt.command.key_generate', GenerateKeyCommand::class)
            ->tag('console.command', ['command' => 'jwt:key:generate']);

        $services->set('medzuch_jwt.command.config_check', CheckConfigurationCommand::class)
            ->args([
                service_locator(self::everythingBuiltLazily($config, $keys)),
                service_locator(array_combine(
                    array_keys($config['remote_jwks']),
                    array_map(
                        static fn(string $name): ReferenceConfigurator => service('medzuch_jwt.remote_jwks.' . $name),
                        array_keys($config['remote_jwks']),
                    ),
                )),
                // A closure, so the set is built when the command asks rather
                // than when the container hands it over: a published key whose
                // file is missing is a row in the report, not an exception
                // instead of one.
                $publishes ? service_closure('medzuch_jwt.jwks.key_set') : null,
            ])
            ->tag('console.command', ['command' => 'jwt:config:check']);

        $services->set('medzuch_jwt.command.token_inspect', InspectTokenCommand::class)
            ->args([
                service_locator(array_combine(
                    $consumers,
                    array_map(static fn(string $name): ReferenceConfigurator => service('medzuch_jwt.handler.' . $name), $consumers),
                )),
                service('medzuch_jwt.clock'),
            ])
            ->tag('console.command', ['command' => 'jwt:token:inspect']);

        if ($publishes) {
            $services->set('medzuch_jwt.command.jwks_dump', DumpJwksCommand::class)
                ->args([service('medzuch_jwt.jwks.key_set')])
                ->tag('console.command', ['command' => 'jwt:jwks:dump']);
        }

        if ([] === $issuers) {
            return;
        }

        $services->set('medzuch_jwt.command.token_create', CreateTokenCommand::class)
            ->args([
                service_locator(array_combine(
                    $issuers,
                    array_map(static fn(string $name): ReferenceConfigurator => service('medzuch_jwt.issuer.' . $name), $issuers),
                )),
            ])
            ->tag('console.command', ['command' => 'jwt:token:create']);
    }

    /**
     * What the container builds only when something asks for it, keyed by the
     * name the report calls it. Key material above all: a `pem_private` is a
     * path or an env reference until a factory reads it, so a file nobody
     * deployed is a configuration that compiles and a request that does not.
     *
     * @param array{keys: array<string, mixed>, issuers: array<string, mixed>, consumers: array<string, mixed>, id_tokens: array<string, mixed>, ...} $config
     * @param array<string, array{hmac: string|null, pem_private: string|null, pem_public: string|null, jwk_private: string|null, jwk_public: string|null, pem_passphrase: string|null, algorithm: string, kid: string|null}>                                        $keys
     *
     * @return array<string, ReferenceConfigurator>
     */
    private static function everythingBuiltLazily(array $config, array $keys): array
    {
        $subjects = [];

        foreach ($keys as $name => $key) {
            if (null !== $key['hmac']) {
                // One row, because there is one key: a shared secret is both
                // halves, and `.signing` and `.verification` are aliases to it.
                // Reported twice, one bad secret would read as two mistakes.
                $subjects[sprintf('key "%s"', $name)] = service('medzuch_jwt.key.' . $name);

                continue;
            }

            foreach (['signing' => self::hasPrivateHalf($key), 'verification' => self::hasPublicHalf($key)] as $half => $configured) {
                if ($configured) {
                    $subjects[sprintf('key "%s" (%s)', $name, $half)] = service(sprintf('medzuch_jwt.key.%s.%s', $name, $half));
                }
            }
        }

        foreach (array_keys($config['consumers']) as $name) {
            // The handler rather than the consumer: it is what the firewall
            // calls, so building it also builds the user resolver and the
            // denylist behind it.
            $subjects[sprintf('consumer "%s"', $name)] = service('medzuch_jwt.handler.' . $name);
        }

        foreach (array_keys($config['issuers']) as $name) {
            $subjects[sprintf('issuer "%s"', $name)] = service('medzuch_jwt.issuer.' . $name);
        }

        foreach (array_keys($config['id_tokens']) as $name) {
            $subjects[sprintf('ID token "%s"', $name)] = service('medzuch_jwt.id_token.' . $name);
        }

        return $subjects;
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

        $levels = $children->arrayNode('log_levels')
            ->addDefaultsIfNotSet()
            ->info('The PSR-3 level each kind of diagnostic is emitted at. The library decides the level; your logger decides whether to record it — so this is how a resource server stops paying for a line per accepted token, or starts alerting on refusals. Unset, each keeps the library\'s default. Read only where a `logger` is configured.')
            ->children();

        foreach (self::LOG_LEVELS as $option => [, $info]) {
            $levels->scalarNode($option)
                ->defaultNull()
                ->info($info)
                ->example('notice')
                ->validate()
                    ->ifTrue(static fn(mixed $value): bool => null !== $value && !in_array($value, LogLevels::all(), true))
                    ->thenInvalid('medzuch_jwt.log_levels.' . $option . ' must be one of the eight PSR-3 levels (' . implode(', ', LogLevels::all()) . '). Got %s')
                ->end()
                ->end();
        }

        $levels->end();

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
     * Named token extractors, for the firewall to reference by service id.
     *
     * Only the cookie one lives here: Symfony ships extractors for the
     * `Authorization` header, the query string and a form-encoded body, and a
     * fourth spelling of those would be a name to learn for no gain. What it
     * does not ship is the one a browser needs, which is why this exists.
     */
    private function configureTokenExtractors(NodeBuilder $children): void
    {
        $extractor = $children->arrayNode('token_extractors')
            ->info('Named token extractors. Reference them from a firewall\'s `access_token.token_extractors`, beside Symfony\'s own security.access_token_extractor.header, .query_string and .request_body.')
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children();

        $extractor->scalarNode('cookie')
            ->isRequired()
            ->cannotBeEmpty()
            ->info('Name of the cookie carrying the token. A `__Host-` prefix is worth having: it makes the browser refuse the cookie unless it is Secure, path-wide and unscoped to a domain, which stops a subdomain from setting one.')
            ->example('__Host-jwt')
            ->validate()
                // A name outside the RFC 6265 §4.1.1 token set is one no
                // browser will ever send under, so the extractor would sit
                // there matching nothing — a build error says that now instead
                // of leaving an authentication that never fires.
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && 1 !== preg_match('/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/', $value))
                // The character list is escaped for sprintf, which thenInvalid()
                // runs the message through: a bare %& is a format specifier.
                ->thenInvalid('A cookie name must be an RFC 6265 §4.1.1 token: letters, digits and !#$%%&\'*+-.^_`|~, with no spaces or separators. A name outside that set is never sent by a browser. Got %s')
            ->end()
            ->end();

        $extractor->booleanNode('same_site_only')
            ->defaultFalse()
            ->info('Ignore the cookie when the browser reports the request as cross-site (`Sec-Fetch-Site`). Defence in depth against CSRF, not a defence: a request without the header — an API client, an older browser — is not judged, so state-changing routes still need their own protection.')
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
            ->ifTrue(static fn(mixed $value): bool => is_array($value) && [] !== array_intersect(array_keys($value), ReservedClaims::REGISTERED))
            ->thenInvalid(sprintf(
                'Static claims cannot include the registered claims %s — they are set from configuration (`issuer`, `audience`, `ttl`) or by the profile. Got %%s',
                '"' . implode('", "', ReservedClaims::REGISTERED) . '"',
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

        $consumer->enumNode('audience_policy')
            ->values(['any', 'exclusive'])
            ->defaultValue('any')
            ->info('How much of the token\'s `aud` has to be ours. "any" is RFC 7519 §4.1.3: the token is for us if it names us, whoever else it names too. "exclusive" also refuses a token addressed to anyone else, which is what RFC 9068 §3 asks of an access token — a token minted for several services only has to leak from the least careful one.')
            ->end();

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

        $consumer->scalarNode('realm')
            ->defaultNull()
            ->cannotBeEmpty()
            ->info('Protection space named in the `WWW-Authenticate` header of this consumer\'s entry point and scope denials (RFC 6750 §3). Null uses the consumer\'s name. Symfony has its own `access_token.realm` for the header it sends itself; keep the two equal. A literal, not an env reference: the value is validated, which is what stops a quote or a newline from costing the header, and Symfony refuses to validate a placeholder.')
            ->example('api')
            ->validate()
                // A quote would close the quoted-string it is interpolated
                // into and let the rest read as further auth-params; a control
                // character is not allowed in one at all (RFC 9110 §5.6.4), and
                // a newline costs the whole header — PHP refuses to emit a
                // header value carrying one, so the 401 goes out with nothing
                // saying how to authenticate. Escaped or stripped on the way
                // out as well, but a realm nobody can read is a configuration
                // mistake worth naming here.
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && (false !== strpbrk($value, "\"\\") || 1 === preg_match(Challenge::CONTROL, $value)))
                ->thenInvalid('A realm cannot contain a quote, a backslash or a control character: it is interpolated into a quoted-string in WWW-Authenticate (RFC 9110 §5.6.4). Got %s')
            ->end()
            ->end();

        $consumer->integerNode('leeway')
            ->defaultValue(0)
            ->min(0)
            ->max(ValidatorBuilder::LEEWAY_CEILING_SECONDS)
            ->info('Clock-skew tolerance in seconds for exp/nbf/iat. The ceiling is the library\'s.')
            ->end();

        self::declareOptionalName(
            $consumer,
            'token_type',
            'The `typ` this consumer expects, for a token whose posture is this application\'s rather than a standard. Naming one verifies the token as a plain JWT with the rules below instead of through the RFC 9068 access-token profile: same keys, algorithms, issuer, audience, leeway and clock, and none of the profile\'s own required claims. Omit it — the default — for the RFC 9068 posture. RFC 7515 §4.1.9 puts the bare form on the wire, so give it without the "application/" prefix.',
            'vnd.acme.session+jwt',
        );

        $required = $consumer->arrayNode('required_claims');
        $required->info('Claims a token must carry, for a consumer that names a `token_type`. Only the presence is checked; what a value means is the application\'s. Left out, it is `["exp"]`: the library checks `exp`, `nbf` and `iat` where a token carries them and nowhere else, so a posture requiring none of them would accept a credential that never stops being valid. A list of your own replaces that — and one omitting `exp` needs `max_token_age` to bound the token instead.');
        $required->scalarPrototype()->cannotBeEmpty()->end();
        $required->defaultValue([]);
        $required->example(['exp', 'sub', 'session_id']);
        self::rejectMaps($required, 'consumers.*.required_claims');

        $consumer->integerNode('max_token_age')
            ->defaultNull()
            ->min(1)
            ->info('Refuse a token older than this many seconds, counted from `iat`, however long its `exp` says it lives. A ceiling of your own on an issuer\'s generosity: a leaked token stops working when this runs out rather than when they decided it should. Off unless set, and `leeway` widens it as it widens every other dated check.')
            ->example('300')
            ->end();

        $denylist = $consumer->arrayNode('denylist')
            ->addDefaultsIfNotSet()
            ->info('Where this consumer asks whether a token has been withdrawn since it was issued. Configured, it costs a lookup per request; unconfigured, nothing is asked and nothing is registered.')
            ->children();

        self::declareOptionalName(
            $denylist,
            'service',
            'Service id implementing TokenDenylistInterface. For a store of your own — the shipped one is a cache, and a cache flush forgets every revocation.',
            'app.token_denylist',
        );

        self::declareOptionalName(
            $denylist,
            'cache_pool',
            'Service id of a PSR-6 cache pool, wrapped for the PSR-16 interface the shipped denylist takes. `cache.app` is a pool.',
            'cache.app',
        );

        self::declareOptionalName(
            $denylist,
            'cache',
            'Service id of a PSR-16 cache, used as it is.',
            'app.simple_cache',
        );

        $denylist->scalarNode('prefix')
            ->defaultValue(self::DEFAULT_DENYLIST_PREFIX)
            ->cannotBeEmpty()
            ->info('Prefix for the cache keys, so revocations do not collide with the rest of the pool. The rest of the key is a hash of the `jti`. PSR-16 §6 reserves {}()/\@: in keys, so those are refused here rather than by the store on every request.')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && strlen($value) > 32)
                ->thenInvalid('A denylist prefix over 32 characters can push the key past the 64 PSR-16 guarantees, once the hash of the jti is appended. Got %s')
            ->end()
            ->validate()
                // strpbrk over the reserved set rather than a character class:
                // the backslash in one is a question about two escaping layers,
                // and the pattern that reads as covering it does not.
                ->ifTrue(static fn(mixed $value): bool => is_string($value) && false !== strpbrk($value, '{}()/\\@:'))
                ->thenInvalid('A denylist prefix cannot contain {}()/\@:, which PSR-16 §6 reserves and Symfony\'s cache refuses. A store rejects such a key on every request that checks one, which is a 500 rather than a configuration error. Got %s')
            ->end()
            ->end();

        $user = $consumer->arrayNode('user')
            ->addDefaultsIfNotSet()
            ->children();

        $user->enumNode('mode')
            ->values(['provider', 'claims', 'custom'])
            ->defaultValue('provider')
            ->info('Where the user comes from. "provider" asks the firewall\'s user provider, which is right when a store is the authority. "claims" builds the user from the token, which is right when the issuer is — a resource server verifying a third party\'s tokens usually has nothing to look up. "custom" hands the claims to a service of yours.')
            ->end();

        $user->scalarNode('identity_claim')
            ->defaultValue('sub')
            ->cannotBeEmpty()
            ->info('Claim whose value identifies the user. In "provider" mode it is what the user provider is asked for; mode "custom" ignores it, because the factory names the user it builds.')
            ->end();

        self::declareOptionalName(
            $user,
            'factory',
            'Service id implementing JwtUserFactoryInterface. Required by mode "custom", and refused by the others, which have their own answer.',
            'app.jwt_user_factory',
        );

        $roles = $user->arrayNode('roles')
            ->addDefaultsIfNotSet()
            ->info('How the token\'s claims become roles. Only mode "claims" reads this: a user provider brings its own roles, and a custom factory decides for itself.')
            ->children();

        self::declareOptionalName(
            $roles,
            'claim',
            'Claim carrying what the token grants — "scope" (RFC 6749 §3.3), "roles", "groups" or whatever your issuer sends. A list or a delimited string; both are read.',
            'scope',
        );

        $roles->scalarNode('separator')
            ->defaultValue(' ')
            ->info('Delimiter, when the claim is a string. A space is what `scope` uses. Null treats a string claim as one whole value.')
            ->validate()
                ->ifTrue(static fn(mixed $value): bool => '' === $value)
                ->thenInvalid('A roles separator cannot be the empty string: splitting on nothing has no meaning. Use null to take the claim whole.')
            ->end()
            ->end();

        $roles->scalarNode('prefix')
            ->defaultValue('ROLE_')
            ->info('Prepended to each value, because Symfony\'s access rules speak in ROLE_*. Set it to an empty string if your issuer already sends them prefixed.')
            ->end();

        $defaults = $roles->arrayNode('defaults');
        $defaults->info('Roles every verified token gets, whatever it claims. Empty unless set: a baseline like ROLE_USER is granted only if you ask for it, and nothing invents one.');
        $defaults->scalarPrototype()->cannotBeEmpty()->end();
        $defaults->defaultValue([]);
        self::rejectMaps($defaults, 'consumers.*.user.roles.defaults');
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
     * @param array<string, string|null> $logLevels
     */
    private function registerRemoteJwks(ServicesConfigurator $services, ContainerBuilder $builder, array $sets, ?string $logger, array $logLevels): void
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
            $this->assertCanVerify(sprintf('Consumer "%s"', $name), $consumer, $keys, $sets);

            self::registerLocalKeySet($services, 'medzuch_jwt.jwk_set.' . $name, $consumer);

            self::assertTokenTypeIsUsable($name, $consumer);

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
                        [] === $consumer['required_claims'] ? self::DEFAULT_REQUIRED_CLAIMS : array_values($consumer['required_claims']),
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
            if (self::DEFAULT_DENYLIST_PREFIX !== $denylist['prefix']) {
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
        self::assertUserModeIsCoherent($name, $user);

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
     * Each mode answers the question a different way, so an option belonging to
     * one of the others is not a harmless extra: it is a statement about the
     * user that nothing will read.
     *
     * @param array{mode: string, identity_claim: string, factory: string|null, roles: array{claim: string|null, separator: string|null, prefix: string, defaults: list<string>}} $user
     */
    private static function assertUserModeIsCoherent(string $name, array $user): void
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
        $written = array_filter($levels, static fn(?string $level): bool => null !== $level);

        if ([] === $written) {
            return null;
        }

        $service = inline_service(LogLevels::class);

        foreach ($written as $option => $level) {
            $service = $service->arg('$' . self::LOG_LEVELS[$option][0], $level);
        }

        return $service;
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
    private static function assertTokenTypeIsUsable(string $name, array $consumer): void
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
