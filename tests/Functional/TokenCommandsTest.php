<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\NestedJwtBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Command\CreateTokenCommand;
use Medzuch\JwtBundle\Command\InspectTokenCommand;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsVerification;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Psr\Clock\ClockInterface;
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

    /** Exactly the 32 bytes A256KW is. */
    private const SEALING = '0123456789abcdef0123456789abcdef';

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

    #[TestDox('a claim the token sets itself is refused before anything is signed, not thrown from a builder')]
    public function testRegisteredClaimIsRefusedAsInput(): void
    {
        // The library refuses these too, but from inside a builder, where the
        // answer is a stack trace that reads like a bug in this bundle.
        $tester = self::console('jwt:token:create', ['subject' => 'alice', '--claim' => ['exp=1']]);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('"exp"', $tester->getDisplay());
    }

    #[TestDox('client_id and scope may still be given as claims, because the issuer says so')]
    public function testTheTwoOverridableClaimsAreStillAllowed(): void
    {
        $token = self::mint([
            'subject' => 'alice',
            '--scope' => ['reports.read'],
            '--claim' => ['scope=reports.write', 'client_id=another'],
            '--raw' => true,
        ]);

        $claims = self::payload($token);

        self::assertSame('reports.write', $claims['scope'] ?? null);
        self::assertSame('another', $claims['client_id'] ?? null);
    }

    #[TestDox('a subject nobody named is refused rather than minted as an empty one')]
    public function testEmptySubjectIsRefused(): void
    {
        $tester = self::console('jwt:token:create', ['subject' => '']);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('cannot be empty', $tester->getDisplay());
    }

    #[TestDox('the only configured issuer is used without being named, whatever it is called')]
    public function testTheOnlyIssuerNeedsNoNaming(): void
    {
        $configuration = self::configuration();
        $configuration['issuers'] = ['partners' => $configuration['issuers']['default']];

        $tester = self::console('jwt:token:create', ['subject' => 'alice', '--raw' => true], null, $configuration);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertSame('alice', self::payload(trim($tester->getDisplay()))['sub'] ?? null);
    }

    #[TestDox('among several issuers with no "default" among them, one has to be named')]
    public function testSeveralIssuersNeedNaming(): void
    {
        $configuration = self::configuration();
        $configuration['issuers'] = [
            'partners' => $configuration['issuers']['default'],
            'internal' => $configuration['issuers']['default'],
        ];

        $tester = self::console('jwt:token:create', ['subject' => 'alice'], null, $configuration);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('Name one with --issuer', $tester->getDisplay());

        // And naming one mints through it.
        $named = self::console('jwt:token:create', ['subject' => 'alice', '--issuer' => 'internal', '--raw' => true], null, $configuration);

        self::assertSame(Command::SUCCESS, $named->getStatusCode(), $named->getDisplay());
    }

    #[TestDox('an option given as an empty string is a mistake, not an option left out')]
    public function testBlankOptionIsRefused(): void
    {
        $create = self::console('jwt:token:create', ['subject' => 'alice', '--issuer' => ' ']);
        self::assertSame(Command::INVALID, $create->getStatusCode());

        $inspect = self::console('jwt:token:inspect', ['token' => self::expiredToken(), '--consumer' => '']);
        self::assertSame(Command::INVALID, $inspect->getStatusCode());
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

    /**
     * Before C12 this printed "not a JWT this bundle can read" and stopped,
     * which was a wrong sentence about a token the bundle reads perfectly
     * well. The claims still cannot be shown — they are encrypted, and this
     * command holds no key — but the outer header can, and the consumer that
     * does hold the key still gives its verdict.
     */
    #[TestDox('an encrypted token shows its outer header and still gets a verdict')]
    public function testEncryptedTokenIsInspected(): void
    {
        $configuration = self::sealedConfiguration();

        $tester = self::console('jwt:token:inspect', ['token' => self::sealed(self::expiredToken())], null, $configuration);

        $display = $tester->getDisplay();

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('Header (encrypted token)', $display);
        self::assertStringContainsString('A256KW', $display);
        self::assertStringContainsString('The claims are encrypted', $display);
        // The verdict comes from the consumer, which opened it: the reason is
        // the expiry of the token inside, not the envelope around it.
        self::assertStringContainsString('refuses this token: expired', $display);
    }

    private static function sealed(string $signed): string
    {
        return (string) NestedJwtBuilder::wrap(
            new CompactJws($signed),
            new A256Kw(),
            new A256Gcm(),
            OctKey::fromBinary(self::SEALING, 'A256KW', 'enc-2026'),
            ['kid' => 'enc-2026'],
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function sealedConfiguration(): array
    {
        $configuration = self::configuration();
        $configuration['jwe_keys'] = ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256KW', 'kid' => 'enc-2026']];
        $configuration['consumers']['api']['jwe'] = [
            'keys' => ['sealed'],
            'allowed_key_management' => ['A256KW'],
            'allowed_content_encryption' => ['A256GCM'],
        ];

        return $configuration;
    }

    #[TestDox('with several consumers configured, inspect refuses to pick one')]
    public function testSeveralConsumersNeedNaming(): void
    {
        $configuration = self::configuration();
        $configuration['consumers']['admin'] = $configuration['consumers']['api'];

        $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken()], null, $configuration);

        // Not SUCCESS: `inspect "$TOKEN" && deploy` would otherwise pass having
        // verified nothing at all.
        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('name a consumer with --consumer', $tester->getDisplay());
        self::assertStringContainsString('"api"', $tester->getDisplay());
        self::assertStringContainsString('"admin"', $tester->getDisplay());

        // Named, it answers for that one.
        $named = self::console('jwt:token:inspect', ['token' => self::expiredToken(), '--consumer' => 'admin'], null, $configuration);

        self::assertSame(Command::FAILURE, $named->getStatusCode());
        self::assertStringContainsString('Consumer "admin" refuses this token: expired', $named->getDisplay());
    }

    #[TestDox('a consumer that is not configured is refused by name, with the ones that are')]
    public function testUnknownConsumerIsRefused(): void
    {
        $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken(), '--consumer' => 'nope']);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('No consumer named "nope"', $tester->getDisplay());
        self::assertStringContainsString('"api"', $tester->getDisplay());
    }

    #[TestDox('console markup inside a token is printed, not obeyed')]
    public function testTokenValuesAreEscaped(): void
    {
        $tester = self::console('jwt:token:inspect', ['token' => self::tokenNaming('<error>root</error>')]);

        $display = $tester->getDisplay();

        // Twice, and the count is the point: once in the claims table and once
        // in the line naming who this token would authenticate as. Unescaped,
        // the formatter eats the tags and prints "root" — a debugging command
        // showing something the token does not say — so either escape going
        // missing drops this to one.
        self::assertSame(2, substr_count($display, '<error>root</error>'), $display);

        // A claim that appears nowhere but the table, so the table's own
        // escaping is pinned rather than inferred.
        self::assertStringContainsString('<info>not a verdict</info>', $display);
    }

    #[TestDox('inspecting a token is announced to the listeners a request would reach')]
    public function testInspectionDispatchesTheSameEvents(): void
    {
        $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken()]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());

        // The deliberate half of verifying through the real handler: an answer
        // reached by a quieter route would not be the firewall's answer.
        $listener = self::getContainer()->get('test.verification_listener');
        self::assertInstanceOf(RecordsVerification::class, $listener);
        self::assertCount(1, $listener->rejected);
        self::assertSame(RejectionReason::Expired, $listener->rejected[0]->reason);
    }

    #[TestDox('instants are rendered in the application clock\'s zone, not the machine\'s')]
    public function testInstantsFollowTheClock(): void
    {
        $timezone = date_default_timezone_get();
        date_default_timezone_set('America/New_York');

        try {
            $tester = self::console('jwt:token:inspect', ['token' => self::expiredToken()]);
        } finally {
            date_default_timezone_set($timezone);
        }

        // Asserted against the clock rather than against a literal, so this
        // says "the rendering follows the clock" and not "UTC happens to be
        // what came out": a token read on a laptop and on the server that
        // refused it should not need an offset undoing between them.
        $clock = self::getContainer()->get('medzuch_jwt.clock');
        self::assertInstanceOf(ClockInterface::class, $clock);

        self::assertStringContainsString($clock->now()->format('P'), $tester->getDisplay());
        self::assertStringNotContainsString('-04:00', $tester->getDisplay());
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

    private static function tokenNaming(string $subject): string
    {
        return (string) AccessTokenProfile::issuer(self::ISSUER, new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'))
            ->issue()
            ->subject($subject)
            ->audience(self::AUDIENCE)
            ->clientId('test-client')
            ->withClaim('note', '<info>not a verdict</info>')
            ->expiresIn(new DateInterval('PT5M'))
            ->build();
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
