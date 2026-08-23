<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Command\CreateTokenCommand;
use Medzuch\JwtBundle\Command\InspectTokenCommand;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Exception\CommandNotFoundException;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The two commands are judged against each other and against the firewall's own
 * handler: what `create` mints, `inspect` accepts, and a token broken on
 * purpose is refused with the reason that broke it.
 */
#[CoversClass(CreateTokenCommand::class)]
#[CoversClass(InspectTokenCommand::class)]
final class TokenCommandsTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('a token this command mints is one the consumer accepts')]
    public function testCreatedTokenIsAccepted(): void
    {
        $token = self::mint(['subject' => 'alice', '--raw' => true]);

        $inspect = self::console('jwt:token:inspect', ['token' => $token]);

        self::assertSame(Command::SUCCESS, $inspect->getStatusCode());
        self::assertStringContainsString('Consumer "api" accepts this token', $inspect->getDisplay());
        self::assertStringContainsString('would authenticate as', $inspect->getDisplay());
        self::assertStringContainsString('alice', $inspect->getDisplay());
    }

    #[TestDox('--raw prints the token and nothing else, so a shell can capture it')]
    public function testRawPrintsOnlyTheToken(): void
    {
        $tester = self::console('jwt:token:create', ['subject' => 'alice', '--raw' => true]);

        $lines = array_values(array_filter(
            explode("\n", $tester->getDisplay()),
            static fn(string $line): bool => '' !== trim($line),
        ));

        self::assertCount(1, $lines);
        self::assertSame(3, substr_count($lines[0], '.') + 1, 'a compact JWS is three dot-separated segments');
    }

    #[TestDox('scopes, audience and lifetime given on the command line reach the token')]
    public function testOptionsReachTheToken(): void
    {
        $token = self::mint([
            'subject' => 'alice',
            '--scope' => ['reports.read', 'reports.write'],
            '--audience' => ['https://reports.test'],
            '--ttl' => '60',
            '--claim' => ['tenant=acme'],
            '--raw' => true,
        ]);

        $claims = self::payload($token);

        self::assertSame('reports.read reports.write', $claims['scope'] ?? null);
        // A list even for one name: the issuer is given a list and the library
        // writes what it is given (RFC 7519 §4.1.3 allows either).
        self::assertSame(['https://reports.test'], $claims['aud'] ?? null);
        self::assertSame('acme', $claims['tenant'] ?? null);
        self::assertIsInt($claims['exp'] ?? null);
        self::assertIsInt($claims['iat'] ?? null);
        self::assertSame(60, $claims['exp'] - $claims['iat']);
    }

    #[TestDox('an issuer that is not configured is refused by name, with the ones that are')]
    public function testUnknownIssuerIsRefused(): void
    {
        $tester = self::console('jwt:token:create', ['subject' => 'alice', '--issuer' => 'partners']);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('No issuer named "partners"', $tester->getDisplay());
        self::assertStringContainsString('"default"', $tester->getDisplay());
    }

    #[TestDox('a lifetime that is not a positive number of seconds is refused before anything is signed')]
    public function testTtlMustBeAPositiveInteger(): void
    {
        foreach (['0', '-30', 'an hour'] as $ttl) {
            $tester = self::console('jwt:token:create', ['subject' => 'alice', '--ttl' => $ttl]);

            self::assertSame(Command::INVALID, $tester->getStatusCode(), sprintf('--ttl %s', $ttl));
        }
    }

    #[TestDox('a claim that is not name=value is refused rather than guessed at')]
    public function testClaimMustBeAPair(): void
    {
        $tester = self::console('jwt:token:create', ['subject' => 'alice', '--claim' => ['tenant']]);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('name=value', $tester->getDisplay());
    }

    #[TestDox('inspect names the reason a consumer refuses a token, which the 401 does not')]
    public function testRefusalNamesItsReason(): void
    {
        $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken()]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('refuses this token: expired', $tester->getDisplay());
    }

    #[TestDox('the claims are shown whether or not anything verifies them')]
    public function testClaimsAreShownBeforeTheVerdict(): void
    {
        $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken()]);

        $display = $tester->getDisplay();

        self::assertStringContainsString('Claims (not verified yet)', $display);
        self::assertStringContainsString('user-42', $display);
        // A moment, rendered as one: a number of seconds since 1970 is not an
        // answer to "when did this expire".
        self::assertMatchesRegularExpression('/exp\s+.*ago/', $display);
    }

    #[TestDox('a token can be piped in')]
    public function testTokenCanBePiped(): void
    {
        $token = self::mint(['subject' => 'alice', '--raw' => true]);

        $tester = self::console('jwt:token:inspect', ['token' => '-'], $token);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('accepts this token', $tester->getDisplay());
    }

    #[TestDox('something that is not a JWT is refused as bad input, not as a bad credential')]
    public function testGarbageIsInvalidInput(): void
    {
        $tester = self::console('jwt:token:inspect', ['token' => 'not-a-token']);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('not a JWT', $tester->getDisplay());
    }

    #[TestDox('with several consumers configured, inspect refuses to pick one')]
    public function testSeveralConsumersNeedNaming(): void
    {
        $configuration = self::configuration();
        $configuration['consumers']['admin'] = $configuration['consumers']['api'];

        $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken()], null, $configuration);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('name a consumer with --consumer', $tester->getDisplay());
        self::assertStringContainsString('"api"', $tester->getDisplay());
        self::assertStringContainsString('"admin"', $tester->getDisplay());
    }

    #[TestDox('with no consumer configured, inspect still decodes and says nothing was verified')]
    public function testDecodingNeedsNoConfiguration(): void
    {
        $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken()], null, ['keys' => []]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('configures no consumers', $tester->getDisplay());
        self::assertStringContainsString('user-42', $tester->getDisplay());
    }

    #[TestDox('without an issuer there is nothing to mint with, and no command offering to')]
    public function testCreateIsAbsentWithoutAnIssuer(): void
    {
        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => ['keys' => []]]);

        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);
        $application = new Application($kernel);

        // Still there, because decoding needs nothing configured.
        $application->find('jwt:token:inspect');

        $this->expectException(CommandNotFoundException::class);
        $application->find('jwt:token:create');
    }

    /**
     * @param array<string, mixed> $input
     */
    private static function mint(array $input): string
    {
        $tester = self::console('jwt:token:create', $input);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        return trim($tester->getDisplay());
    }

    /**
     * @param array<string, mixed>    $input
     * @param array<string, mixed>|null $configuration
     */
    private static function console(string $command, array $input, ?string $piped = null, ?array $configuration = null): CommandTester
    {
        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => $configuration ?? self::configuration()]);

        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);

        $application = new Application($kernel);
        $application->setAutoExit(false);

        // Found through the console rather than pulled out of the container: a
        // command the application cannot find is a command nobody can run,
        // whatever the service definition says.
        $tester = new CommandTester($application->find($command));

        if (null !== $piped) {
            $tester->setInputs([$piped]);
        }

        $tester->execute($input);

        return $tester;
    }

    /**
     * @return array<string, mixed>
     */
    private static function payload(string $token): array
    {
        $segments = explode('.', $token);
        self::assertCount(3, $segments);

        $json = base64_decode(strtr($segments[1], '-_', '+/'), true);
        self::assertIsString($json);

        $claims = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($claims);

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    private static function expiredToken(): string
    {
        return (string) AccessTokenProfile::issuer(self::ISSUER, new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'))
            ->issue()
            ->subject('user-42')
            ->audience(self::AUDIENCE)
            ->clientId('test-client')
            ->expiresAt(new DateTimeImmutable('-1 hour'))
            ->build();
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, issuers: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function configuration(): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => [
                'issuer' => self::ISSUER,
                'key' => 'default',
                'client_id' => 'test-client',
                'audience' => self::AUDIENCE,
            ]],
            'consumers' => ['api' => [
                'issuer' => self::ISSUER,
                'audience' => self::AUDIENCE,
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
            ]],
        ];
    }
}
