<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\Jwt\Key\JwkSet;
use Medzuch\Jwt\Key\Resolver\RemoteJwksResolver;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\JwtBundle\Command\CheckConfigurationCommand;
use Medzuch\JwtBundle\Tests\Functional\App\StubHttpClient;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The command exists for configuration that compiles and does not work, so
 * every case here is exactly that: a container that builds cleanly and a piece
 * of material that is missing, empty or unreachable behind it.
 */
#[CoversClass(CheckConfigurationCommand::class)]
final class CheckConfigurationCommandTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const URI = 'https://idp.test/.well-known/jwks.json';

    private const ISSUER = 'https://idp.test';

    private const DISCOVERY = self::ISSUER . '/.well-known/openid-configuration';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('a configuration whose material is all there passes, and says what it looked at')]
    public function testEverythingBuilds(): void
    {
        $tester = self::check();

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        $display = $tester->getDisplay();
        // One row for the shared secret, not two: it is both halves, and
        // `.signing` and `.verification` are aliases to the one service. Two
        // rows would read as two mistakes when the secret is wrong.
        self::assertStringContainsString('key "default"', $display);
        self::assertStringNotContainsString('(signing)', $display);
        self::assertStringContainsString('consumer "api"', $display);
        self::assertStringContainsString('issuer "default"', $display);
    }

    #[TestDox('a key file nobody deployed is what this command is for')]
    public function testMissingKeyMaterial(): void
    {
        $configuration = self::configuration();
        $configuration['keys'] = [
            'default' => ['pem_public' => '/nowhere/never-deployed.pem', 'algorithm' => 'RS256'],
        ];
        $configuration['consumers']['api']['allowed_algorithms'] = ['RS256'];
        unset($configuration['issuers']);

        // The container builds: a path is a factory argument, and a factory
        // runs when something asks for the service — on a request, normally.
        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('key "default" (verification)', $tester->getDisplay());
        self::assertStringContainsString('FAIL', $tester->getDisplay());

        // And the consumer behind it, because building a handler builds the
        // key it verifies with. One mistake, both rows, which is what an
        // operator needs to see.
        self::assertSame(2, substr_count($tester->getDisplay(), 'FAIL'));
    }

    #[TestDox('a secret too short for the algorithm it is bound to is caught before a request finds it')]
    public function testSecretShorterThanItsAlgorithm(): void
    {
        $configuration = self::configuration();
        // RFC 8725 §3.5 wants 64 bytes for HS512. The container has no opinion:
        // the length is checked by the key, and the key is built lazily.
        $configuration['keys'] = ['default' => ['hmac' => self::SECRET, 'algorithm' => 'HS512']];
        $configuration['consumers']['api']['allowed_algorithms'] = ['HS512'];
        $configuration['issuers']['default']['key'] = 'default';

        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('at least 64 bytes', $tester->getDisplay());

        // The key once and the two things built from it: one mistake, three
        // rows, none of them a second copy of the key itself.
        self::assertSame(3, substr_count($tester->getDisplay(), 'FAIL'));
    }

    /**
     * The one length in this bundle nothing else can catch. An HMAC secret has
     * a floor; a JWE key has an exact size — 32 bytes for A256KW, 64 for
     * A256CBC-HS512 — and the value is an env reference while the container is
     * built, so this command is where a deploy finds out.
     */
    #[TestDox('a JWE secret of the wrong length is caught before an encrypted token finds it')]
    public function testJweSecretOfTheWrongLength(): void
    {
        $configuration = self::configuration();
        $configuration['jwe_keys'] = ['sealed' => ['secret' => 'sixteen-bytes!!!', 'algorithm' => 'A256KW', 'kid' => 'enc-2026']];
        $configuration['consumers']['api']['jwe'] = [
            'keys' => ['sealed'],
            'allowed_key_management' => ['A256KW'],
            'allowed_content_encryption' => ['A256GCM'],
        ];

        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('JWE key "sealed"', $tester->getDisplay());
        self::assertStringContainsString('exactly 32 bytes', $tester->getDisplay());
    }

    /**
     * The one dispatcher question the container cannot answer: two tenants
     * whose *different* env references resolve to the same issuer. Written the
     * same way they are refused at build; written as two variables that happen
     * to hold one URL, nothing can see it until something reads them — so this
     * row is that something, and where a deploy finds out instead of a request
     * being routed to whichever tenant was listed first.
     */
    #[TestDox('two tenants expecting one issuer is a row in the report, not a routed token')]
    public function testDispatcherWithAmbiguousRoutes(): void
    {
        $_ENV['OTHER_TENANT_ISSUER'] = 'https://issuer.test';
        putenv('OTHER_TENANT_ISSUER=https://issuer.test');

        $configuration = self::configuration();
        $configuration['consumers']['other'] = ['issuer' => '%env(OTHER_TENANT_ISSUER)%'] + $configuration['consumers']['api'];
        $configuration['dispatchers'] = ['tenants' => ['consumers' => ['api', 'other']]];

        try {
            $tester = self::check(configuration: $configuration);
        } finally {
            unset($_ENV['OTHER_TENANT_ISSUER']);
            putenv('OTHER_TENANT_ISSUER');
        }

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('dispatcher "tenants"', $tester->getDisplay());
        self::assertStringContainsString('cannot choose between consumers', $tester->getDisplay());
    }

    #[TestDox('an issuer that cannot be reached fails the check, and --skip-remote leaves it alone')]
    public function testRemoteSetIsReached(): void
    {
        $configuration = self::remoteConfiguration();

        $tester = self::check(configuration: $configuration, publish: true);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('remote JWK Set "partner_idp"', $tester->getDisplay());
        self::assertStringContainsString('reachable', $tester->getDisplay());

        $offline = self::check(configuration: $configuration, publish: false);

        self::assertSame(Command::FAILURE, $offline->getStatusCode());
        self::assertStringContainsString('remote JWK Set "partner_idp"', $offline->getDisplay());

        // The same broken endpoint, and a gate that has no network to reach it
        // with: what it cannot check, it says it did not check.
        $skipped = self::check(['--skip-remote' => true], $configuration, publish: false);

        self::assertSame(Command::SUCCESS, $skipped->getStatusCode(), $skipped->getDisplay());
        self::assertStringContainsString('skipped', $skipped->getDisplay());
    }

    #[TestDox('the published document is counted, and read for what must never be in it')]
    public function testPublishedSetIsInspected(): void
    {
        $configuration = self::configuration();
        $configuration['keys']['publishable'] = [
            'pem_public' => self::keypair('check-rsa')['public'],
            'algorithm' => 'RS256',
            'kid' => 'rsa-2026',
        ];
        $configuration['jwks'] = ['keys' => ['publishable']];

        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('published JWK Set', $tester->getDisplay());
        self::assertStringContainsString('1 public key(s)', $tester->getDisplay());
    }

    #[TestDox('a published set carrying private material fails, whatever put it there')]
    public function testPublishedSetCarryingPrivateMaterial(): void
    {
        // Built by hand, because no configuration can produce it: the container
        // refuses a symmetric key under `jwks`, and a public half has no private
        // members to leak. That is the point — this row is the last line, for a
        // mistake in the wiring or in a hand-written JWK rather than in the
        // configuration the earlier checks already cover.
        $set = JwkSet::of(RsaPrivateKey::fromPem(self::keypair('leaky')['private'], 'RS256', 'oops'));

        /** @var ServiceLocator<object> $nothing */
        $nothing = new ServiceLocator([]);
        /** @var ServiceLocator<RemoteJwksResolver> $noRemote */
        $noRemote = new ServiceLocator([]);

        $command = new CheckConfigurationCommand($nothing, $noRemote, static fn(): JwkSet => $set);
        $command->setName('jwt:config:check');

        $tester = new CommandTester($command);
        $tester->execute([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('private material', $tester->getDisplay());
    }

    /**
     * The three named things that sign, each of which the command has to know
     * about separately: an access-token issuer, a security-event stream, and
     * an ID token provider. A row that stops being built is a deploy gate that
     * stops covering a key, and nothing else would notice.
     */
    #[TestDox('every kind of issuer is a row, so a dropped loop is not a silent gap')]
    public function testEveryIssuerKindIsBuilt(): void
    {
        $configuration = self::configuration();
        $configuration['id_token_issuers'] = ['op' => ['issuer' => 'https://issuer.test', 'key' => 'default']];
        $configuration['security_events'] = ['issuers' => ['risc' => ['issuer' => 'https://issuer.test', 'key' => 'default']]];

        $tester = self::check(configuration: $configuration);

        $display = $tester->getDisplay();

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $display);
        self::assertStringContainsString('issuer "default"', $display);
        self::assertStringContainsString('ID token issuer "op"', $display);
        self::assertStringContainsString('security event stream "risc"', $display);
    }

    #[TestDox('an ID-token verifier is checked like everything else')]
    public function testIdTokenRegistrationIsChecked(): void
    {
        $configuration = self::configuration();
        $configuration['keys']['partner'] = [
            'pem_public' => self::keypair('check-idp')['public'],
            'algorithm' => 'RS256',
            'kid' => 'partner-2026',
        ];
        $configuration['id_tokens'] = ['partner' => [
            'issuer' => 'https://idp.test',
            'client_id' => 'this-application',
            'keys' => ['partner'],
            'allowed_algorithms' => ['RS256'],
        ]];

        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('ID token "partner"', $tester->getDisplay());

        // And it fails like everything else when its key is not there, which is
        // what stops the loop that collects them from being dropped quietly.
        $configuration['keys']['partner'] = ['pem_public' => '/nowhere/never-deployed.pem', 'algorithm' => 'RS256'];

        $broken = self::check(configuration: $configuration);

        self::assertSame(Command::FAILURE, $broken->getStatusCode());
        self::assertStringContainsString('ID token "partner"', $broken->getDisplay());
    }

    #[TestDox('both halves of a security event stream are built by the check')]
    public function testSecurityEventsAreChecked(): void
    {
        // The command promises to build every configured verifier, and a
        // capability whose services it never instantiates is one where
        // `jwt:config:check && deploy` goes green on a key that was never read.
        $configuration = self::configuration();
        $configuration['keys']['risc'] = [
            'pem_private' => self::keypair('check-risc')['private'],
            'pem_public' => self::keypair('check-risc')['public'],
            'algorithm' => 'RS256',
            'kid' => 'risc-2026',
        ];
        $configuration['security_events'] = [
            'issuers' => ['stream' => ['issuer' => 'https://issuer.test', 'key' => 'risc']],
            'consumers' => ['partner' => [
                'issuer' => 'https://idp.test',
                'keys' => ['risc'],
                'allowed_algorithms' => ['RS256'],
            ]],
        ];

        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('security event stream "stream"', $tester->getDisplay());
        self::assertStringContainsString('security event consumer "partner"', $tester->getDisplay());

        // And both fail when the key behind them is not deployed, which is what
        // stops the two loops that collect them from being dropped quietly.
        $configuration['keys']['risc'] = [
            'pem_private' => '/nowhere/never-deployed.pem',
            'pem_public' => '/nowhere/never-deployed.pub.pem',
            'algorithm' => 'RS256',
        ];

        $broken = self::check(configuration: $configuration);

        self::assertSame(Command::FAILURE, $broken->getStatusCode());
        self::assertStringContainsString('security event stream "stream"', $broken->getDisplay());
        self::assertStringContainsString('security event consumer "partner"', $broken->getDisplay());
    }

    #[TestDox('the metadata document is built by the check, where an env var is finally read')]
    public function testMetadataDocumentIsChecked(): void
    {
        // O5's whole shape: the controller is the only place a `%env(APP_URL)%`
        // has a value, so without this row a plaintext identifier passes
        // `jwt:config:check && deploy` and fails on the first well-known
        // request — configuration that compiles and does not work.
        $configuration = self::configuration();
        $configuration['metadata'] = [
            'issuer' => 'https://api.test',
            'jwks_uri' => 'https://api.test/.well-known/jwks.json',
            'extra' => ['response_types_supported' => ['code']],
        ];

        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('metadata document', $tester->getDisplay());

        // And it fails when the identifier turns out not to be publishable,
        // which is what stops the row from being dropped quietly.
        putenv('JWT_TEST_CHECK_ISSUER=http://api.test');

        try {
            $configuration['metadata']['issuer'] = '%env(JWT_TEST_CHECK_ISSUER)%';

            $broken = self::check(configuration: $configuration);

            self::assertSame(Command::FAILURE, $broken->getStatusCode());
            self::assertStringContainsString('metadata document', $broken->getDisplay());
        } finally {
            putenv('JWT_TEST_CHECK_ISSUER');
        }
    }

    #[TestDox('a published key whose file is missing is a row, not an exception instead of one')]
    public function testMissingPublishedKeyIsReported(): void
    {
        $configuration = self::configuration();
        $configuration['keys']['published'] = ['pem_public' => '/nowhere/never-deployed.pem', 'algorithm' => 'RS256'];
        $configuration['jwks'] = ['keys' => ['published']];

        $tester = self::check(configuration: $configuration);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());

        $display = $tester->getDisplay();

        // The published set fails, and so does the key behind it — but the rest
        // of the report is still there. Built when the command was constructed
        // rather than when it ran, this key would have thrown before the first
        // row was printed and taken every other check with it.
        self::assertStringContainsString('published JWK Set', $display);
        self::assertStringContainsString('key "published" (verification)', $display);
        self::assertStringContainsString('consumer "api"', $display);
        self::assertStringContainsString('issuer "default"', $display);
    }

    #[TestDox('an application that configures nothing is told so rather than shown an empty table')]
    public function testNothingToCheck(): void
    {
        $tester = self::check(configuration: ['keys' => []]);

        // Not 0: `jwt:config:check && deploy` would go green having checked
        // nothing, which is what a package file that failed to deploy looks
        // like from here.
        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('configures nothing', $tester->getDisplay());
    }

    #[TestDox('a set addressed by issuer identifier is probed over both hops')]
    public function testDiscoveredSetIsReached(): void
    {
        // What makes the probe worth having for a discovery set: it is two
        // round trips, and either can be the one that is broken on the day of
        // the deploy. The pair of URLs is the assertion — a probe that reached
        // only the endpoint would report the same "reachable" on an issuer
        // whose metadata does not resolve at all.
        $configuration = self::remoteConfiguration(discovery: self::ISSUER);

        $tester = self::check(configuration: $configuration, publish: true, announceAt: self::DISCOVERY);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('remote JWK Set "partner_idp"', $tester->getDisplay());
        self::assertStringContainsString('reachable', $tester->getDisplay());

        $client = self::getContainer()->get('test.http_client');
        self::assertInstanceOf(StubHttpClient::class, $client);
        self::assertSame([self::DISCOVERY, self::URI], $client->requested);

        // The issuer that answers nothing at all: the failure is the metadata
        // hop, and it is the one reported.
        $silent = self::check(configuration: $configuration, publish: false);

        self::assertSame(Command::FAILURE, $silent->getStatusCode());
        self::assertStringContainsString('remote JWK Set "partner_idp"', $silent->getDisplay());
        self::assertStringContainsString('Discovery fetch from', $silent->getDisplay());
    }

    /**
     * @param array<string, mixed>      $input
     * @param array<string, mixed>|null $configuration
     */
    private static function check(array $input = [], ?array $configuration = null, ?bool $publish = null, ?string $announceAt = null): CommandTester
    {
        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => $configuration ?? self::configuration()]);

        if (null !== $publish) {
            $client = self::getContainer()->get('test.http_client');
            self::assertInstanceOf(StubHttpClient::class, $client);

            $publish
                ? $client->publishes(self::document())
                : $client->goesOffline();

            if (null !== $announceAt) {
                $client->publishesAt($announceAt, json_encode([
                    'issuer' => self::ISSUER,
                    'jwks_uri' => self::URI,
                ], \JSON_THROW_ON_ERROR));
            }
        }

        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);

        $application = new Application($kernel);
        $application->setAutoExit(false);

        $tester = new CommandTester($application->find('jwt:config:check'));
        $tester->execute($input);

        return $tester;
    }

    private static function document(): string
    {
        $jwk = RsaPrivateKey::fromPem(self::keypair('remote-idp')['private'], 'RS256', 'partner-2026')
            ->toPublicKey()
            ->toJwk();

        return json_encode(['keys' => [$jwk]], \JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<string, mixed>
     */
    private static function remoteConfiguration(?string $discovery = null): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'remote_jwks' => ['partner_idp' => [
                ...(null === $discovery ? ['uri' => self::URI] : ['discovery' => $discovery]),
                'http_client' => 'test.http_client',
                'cache' => 'test.cache',
            ]],
            'consumers' => ['partner' => [
                'issuer' => 'https://idp.test',
                'audience' => 'https://api.test',
                'remote_jwks' => 'partner_idp',
                'allowed_algorithms' => ['RS256'],
            ]],
        ];
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, issuers: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function configuration(): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => [
                'issuer' => 'https://issuer.test',
                'key' => 'default',
                'client_id' => 'test-client',
                'audience' => 'https://api.test',
            ]],
            'consumers' => ['api' => [
                'issuer' => 'https://issuer.test',
                'audience' => 'https://api.test',
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
            ]],
        ];
    }
}
