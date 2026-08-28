<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Event\JwtIssuedEvent;
use Medzuch\JwtBundle\Event\JwtIssuingEvent;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Tests\Functional\App\CollectingLogger as TestLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * A kernel with a real firewall in front of a real controller, so the round
 * trip a bundle promises — mint a token, present it, be someone — is asserted
 * through Symfony's own authenticator rather than by calling our handler.
 */
final class SecuredKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param array<array-key, mixed> $bundleConfig configuration under the `medzuch_jwt` root key
     */
    public function __construct(
        private readonly array $bundleConfig = [],
        private readonly bool $issuanceHooks = false,
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new MedzuchJwtBundle();
    }

    public function getCacheDir(): string
    {
        return sprintf(
            '%s/medzuch-jwt-bundle-tests/secured-php%d-sf%d-%s-%s',
            sys_get_temp_dir(),
            \PHP_VERSION_ID,
            Kernel::VERSION_ID,
            SourceFingerprint::current(),
            hash('xxh128', serialize([$this->bundleConfig, $this->issuanceHooks])),
        );
    }

    /**
     * Points away from the repository: with the project dir defaulting to the
     * package root, booting a kernel writes generated artefacts (a 68 KB
     * `config/reference.php`, among others) straight into the bundle's own
     * `config/` — a source directory here, not an application's.
     */
    public function getProjectDir(): string
    {
        return $this->getCacheDir();
    }

    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new PublicForTestsPass(), PassConfig::TYPE_BEFORE_REMOVING);
        $container->addCompilerPass(new RecordsTaggedServicesPass(), PassConfig::TYPE_BEFORE_REMOVING);
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test-secret',
            'test' => true,
            'router' => ['utf8' => true],
        ]);

        // Firewalls follow the configuration, the way an application's would:
        // a kernel that publishes a JWK Set and nothing else has no login to
        // wire and no consumer to point a firewall at.
        $firewalls = [];

        if (self::configures($this->bundleConfig, 'issuers', 'default')) {
            $firewalls['login'] = [
                'pattern' => '^/login',
                'stateless' => true,
                'provider' => 'users',
                'json_login' => [
                    'check_path' => '/login',
                    'success_handler' => 'medzuch_jwt.login.default',
                ],
            ];
        }

        if (self::configures($this->bundleConfig, 'consumers', 'api')) {
            // Symfony's realm, which its own rejected-token header carries.
            // It is a second knob beside the consumer's, and the two are worth
            // keeping equal — the README says so, and this is what proves the
            // README right.
            $accessToken = ['token_handler' => 'medzuch_jwt.handler.api', 'realm' => 'reports-api'];

            // The firewall names the extractors, as an application's would:
            // the bundle registers them, security.yaml chooses them, and the
            // header one stays first so the ordinary client is unaffected.
            if (self::configures($this->bundleConfig, 'token_extractors', 'cookie')) {
                $accessToken['token_extractors'] = [
                    'security.access_token_extractor.header',
                    'medzuch_jwt.token_extractor.cookie',
                ];
            }

            $firewalls['api'] = [
                'pattern' => '^/api',
                'stateless' => true,
                'provider' => 'users',
                'entry_point' => 'medzuch_jwt.entry_point.api',
                'access_denied_handler' => 'medzuch_jwt.access_denied.api',
                'access_token' => $accessToken,
            ];
        }

        $accessControl = [
            // Before the catch-all below, and narrower: an attribute only the
            // scope voter answers.
            ['path' => '^/api/scoped', 'roles' => 'SCOPE_reports.read'],
            // The prefix with nothing after it, which the voter answers and
            // denies: no token grants the empty scope.
            ['path' => '^/api/bare-scope', 'roles' => 'SCOPE_'],
            // A denial with no scope in it, so the bearer challenge has
            // nothing to add and Symfony's own 403 stands.
            ['path' => '^/api/role', 'roles' => 'ROLE_NOBODY_HAS_THIS'],
            // Attributes the bundle never sees until a request is denied, and
            // neither of which is a scope: one carries a newline, the other a
            // space, and RFC 6749 §3.3 allows neither in a scope-token.
            ['path' => '^/api/dodgy-scope', 'roles' => "SCOPE_reports.read\r\nX-Injected: yes"],
            ['path' => '^/api/spaced-scope', 'roles' => 'SCOPE_reports read'],
            // Identity without a requirement (C15): the path sits behind the
            // same `access_token` firewall as everything else, and is exempted
            // from the catch-all below rather than from the firewall.
            ['path' => '^/api/optional', 'roles' => 'PUBLIC_ACCESS'],
            ['path' => '^/api', 'roles' => 'IS_AUTHENTICATED_FULLY'],
        ];

        // The shape the README warns about: everything behind a firewall, a
        // catch-all access rule, and the JWK Set exempted ahead of it. Served
        // outside any firewall the endpoint answers 200 whatever the rules
        // say, and the warning would have nothing to fail against.
        if (self::publishes($this->bundleConfig)) {
            $firewalls['public'] = ['pattern' => '^/', 'stateless' => true, 'provider' => 'users'];
            array_unshift($accessControl, ['path' => '^/\\.well-known/jwks\\.json$', 'roles' => 'PUBLIC_ACCESS']);
            $accessControl[] = ['path' => '^/', 'roles' => 'IS_AUTHENTICATED_FULLY'];
        }

        $container->extension('security', [
            'password_hashers' => [InMemoryUser::class => ['algorithm' => 'plaintext']],
            'providers' => [
                'users' => ['memory' => ['users' => ['alice' => ['password' => 'open-sesame', 'roles' => ['ROLE_USER']]]]],
            ],
            'firewalls' => [] === $firewalls ? ['none' => ['security' => false]] : $firewalls,
            'access_control' => $accessControl,
        ]);

        $container->extension('medzuch_jwt', $this->bundleConfig);

        $container->services()
            ->set(NeverReachedController::class)
            ->public()

            ->set(WhoAmIController::class)
            ->autowire()
            ->public()

            // Without Monolog, Symfony's fallback logger writes every firewall
            // decision to stderr, which PHPUnit reports as unexpected output.
            // Collecting rather than discarding: a silenced kernel also
            // silences the deprecations and errors a round trip would report.
            ->set('logger', TestLogger::class)->public()

            // A factory an application would own, for the custom user mode. It
            // costs the tests that ignore it nothing, and a mode this kernel
            // could not exercise would be a mode no firewall test can reach.
            ->set('test.user_factory', TenantUserFactory::class)->public()

            // A denylist store the tests can revoke through.
            ->set('test.cache', ArrayCache::class)->public()

            // A clock a test can move, for the same reason TestKernel has one:
            // `medzuch_jwt.clock` is what every consumer, issuer and denylist
            // reads, so freezing it is the only way to watch a token expire
            // without sleeping through it.
            ->set('test.frozen_clock', FrozenClock::class)
            ->factory([FrozenClock::class, 'at'])
            ->args(['2026-01-01T00:00:00+00:00'])
            ->public()

            ->set(ScopedController::class)->public();

        if (!$this->issuanceHooks) {
            return;
        }

        $container->services()
            // Tagged by nothing but the interface: autoconfiguration is the
            // registration a claim provider is meant to need, and a test that
            // tagged it by hand would never notice if that stopped working.
            ->set('test.claims.tenant', TenantClaims::class)->args(['acme'])->autoconfigure()->public()

            // The same interface with a priority, so ordering is asserted
            // rather than assumed: this one runs first and is overridden by
            // the one above, which runs later.
            ->set('test.claims.first', TenantClaims::class)->args(['first-in'])->public()
            ->tag('medzuch_jwt.token_claim_provider', ['priority' => 10])

            ->set('test.issuance_listener', RecordsIssuance::class)->public()
            ->tag('kernel.event_listener', ['event' => JwtIssuingEvent::class, 'method' => 'onIssuing'])
            ->tag('kernel.event_listener', ['event' => JwtIssuedEvent::class, 'method' => 'onIssued']);
    }

    /**
     * @param array<array-key, mixed> $config
     */
    private static function publishes(array $config): bool
    {
        $jwks = $config['jwks'] ?? null;

        return is_array($jwks) && [] !== ($jwks['keys'] ?? []);
    }

    /**
     * @param array<array-key, mixed> $config
     */
    private static function configures(array $config, string $section, string $name): bool
    {
        $entries = $config[$section] ?? null;

        return is_array($entries) && isset($entries[$name]);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('whoami', '/api/whoami')->controller(WhoAmIController::class);
        $routes->add('scoped', '/api/scoped')->controller(WhoAmIController::class);
        // Answers for a caller who may or may not have said who they are.
        $routes->add('optional', '/api/optional')->controller(WhoAmIController::class);
        $routes->add('bare_scope', '/api/bare-scope')->controller(WhoAmIController::class);
        $routes->add('role_only', '/api/role')->controller(WhoAmIController::class);
        $routes->add('dodgy_scope', '/api/dodgy-scope')->controller(WhoAmIController::class);
        $routes->add('spaced_scope', '/api/spaced-scope')->controller(WhoAmIController::class);
        // Guarded by an attribute rather than an access rule: a different
        // listener, the same voter.
        $routes->add('attribute_scoped', '/api/attribute-scoped')->controller(ScopedController::class);

        // Where a JWK Set lives is the application's decision, and this
        // application makes it the way any other would: it routes to the
        // controller when it has configured keys to publish.
        if (self::publishes($this->bundleConfig)) {
            $routes->add('jwks', '/.well-known/jwks.json')
                ->methods(['GET'])
                ->controller('medzuch_jwt.jwks_controller');

            // A sibling under the same firewall and the same catch-all rule,
            // routed so that the router does not 404 the request before
            // security sees it. Its refusal is what shows the exemption above
            // is doing the work.
            $routes->add('well_known_probe', '/.well-known/probe')->controller(NeverReachedController::class);
        }

        // json_login intercepts this path before routing; the route exists so
        // that a request which somehow reaches the router gets a 500 naming the
        // problem rather than a 404 suggesting a typo.
        $routes->add('login', '/login')->methods(['POST'])->controller(NeverReachedController::class);
    }
}
