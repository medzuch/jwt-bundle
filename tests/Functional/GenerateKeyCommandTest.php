<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Command\GenerateKeyCommand;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Yaml\Yaml;

/**
 * The command is judged by whether what it prints works.
 *
 * Each case here runs it, takes the configuration block out of its output, and
 * boots a second kernel from that block — so a snippet naming an option that
 * does not exist, a file it did not write, or a `kid` the document disagrees
 * with fails here rather than in somebody's project.
 */
#[CoversClass(GenerateKeyCommand::class)]
final class GenerateKeyCommandTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private static string $directory = '';

    public static function setUpBeforeClass(): void
    {
        self::$directory = sys_get_temp_dir() . '/jwt-bundle-keygen-' . bin2hex(random_bytes(6));

        // Created here rather than left to the first case that writes into it:
        // a case run alone would otherwise chdir() into a directory that does
        // not exist, stay where it was, and write key files into the repository.
        mkdir(self::$directory, 0o700, true);
    }

    public static function tearDownAfterClass(): void
    {
        self::remove(self::$directory);
        self::$directory = '';
    }

    /** GLOB_BRACE is a glibc extension the test image does not have. */
    private static function remove(string $path): void
    {
        $entries = glob($path . '/*');

        foreach (false === $entries ? [] : $entries as $entry) {
            is_dir($entry) ? self::remove($entry) : @unlink($entry);
        }

        @rmdir($path);
    }

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function formats(): iterable
    {
        yield 'RS256 as PEM' => ['RS256', 'pem', 'pem'];
        yield 'ES256 as JWK' => ['ES256', 'jwk', 'jwk.json'];
        // The one the bundle could not configure before this release: RFC 8037
        // gives Ed25519 no PEM spelling, so a JWK source is what reaches it.
        yield 'EdDSA as JWK' => ['EdDSA', 'jwk', 'jwk.json'];
    }

    #[DataProvider('formats')]
    #[TestDox('a $algorithm key it generates signs and verifies through the configuration it prints')]
    public function testGeneratedKeyWorksThroughThePrintedConfiguration(string $algorithm, string $format, string $extension): void
    {
        $name = strtolower($algorithm);
        $tester = self::generate([
            'algorithm' => $algorithm,
            '--kid' => '2026-08',
            '--name' => $name,
            '--format' => $format,
            '--out' => self::$directory,
        ]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertFileExists(sprintf('%s/%s.private.%s', self::$directory, $name, $extension));
        self::assertFileExists(sprintf('%s/%s.public.%s', self::$directory, $name, $extension));

        $configuration = self::snippet($tester->getDisplay());
        self::assertSame(['algorithm' => $algorithm, 'kid' => '2026-08'], array_intersect_key($configuration['keys'][$name], ['algorithm' => null, 'kid' => null]));

        self::assertSame('user-42', self::roundTrip($configuration, $name, $algorithm));
    }

    #[TestDox('a relative --out is anchored to the project directory, not to whoever runs the container')]
    public function testRelativeOutIsAnchored(): void
    {
        $previous = getcwd();
        self::assertIsString($previous);

        // The container builds the key when it is first needed, in php-fpm's
        // working directory or a worker's — not in the one the console ran in.
        // A relative path copied into the configuration works here and fails
        // there, on the first request that signs.
        self::assertTrue(chdir(self::$directory), 'the relative case is only meaningful from a known directory');

        try {
            $tester = self::generate(['algorithm' => 'ES256', '--name' => 'relative', '--out' => 'config/jwt']);
        } finally {
            chdir($previous);
        }

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertFileExists(self::$directory . '/config/jwt/relative.private.pem');

        $configuration = self::snippet($tester->getDisplay());

        self::assertSame('%kernel.project_dir%/config/jwt/relative.private.pem', $configuration['keys']['relative']['pem_private']);
        self::assertSame('%kernel.project_dir%/config/jwt/relative.public.pem', $configuration['keys']['relative']['pem_public']);
    }

    #[TestDox('the printed paths are anchored even when nothing was written')]
    public function testPrintedKeyIsAnchoredToo(): void
    {
        $tester = self::generate(['algorithm' => 'ES256', '--name' => 'printed']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertStringContainsString('-----BEGIN', $tester->getDisplay());

        $configuration = self::snippet($tester->getDisplay());

        self::assertSame('%kernel.project_dir%/config/jwt/printed.private.pem', $configuration['keys']['printed']['pem_private']);
    }

    #[TestDox('an option the algorithm cannot use is refused rather than quietly ignored')]
    public function testUnusableOptions(): void
    {
        $secretAsJwk = self::generate(['algorithm' => 'HS256', '--format' => 'jwk']);

        self::assertSame(Command::INVALID, $secretAsJwk->getStatusCode());
        self::assertStringContainsString('--format applies to key pairs', $secretAsJwk->getDisplay());

        $curveWithBits = self::generate(['algorithm' => 'ES256', '--bits' => '4096', '--out' => self::$directory]);

        self::assertSame(Command::INVALID, $curveWithBits->getStatusCode());
        self::assertStringContainsString('--bits sizes an RSA modulus', $curveWithBits->getDisplay());
    }

    #[TestDox('the public half is refused as firmly as the private one, and nothing is left behind')]
    public function testPublicHalfIsAlsoNeverReplaced(): void
    {
        $path = self::$directory . '/half.public.pem';
        file_put_contents($path, 'someone else was here');

        $tester = self::generate(['algorithm' => 'ES256', '--name' => 'half', '--out' => self::$directory]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('already exists', $tester->getDisplay());
        self::assertSame('someone else was here', file_get_contents($path));
        self::assertFileDoesNotExist(self::$directory . '/half.private.pem');
    }

    #[TestDox('the private half is written for its owner only')]
    public function testPrivateKeyIsNotReadableByOthers(): void
    {
        self::generate(['algorithm' => 'ES256', '--name' => 'perms', '--out' => self::$directory]);

        $path = self::$directory . '/perms.private.pem';

        self::assertFileExists($path);
        self::assertSame('0600', substr(sprintf('%o', fileperms($path)), -4));
    }

    #[TestDox('a second run refuses to replace a key rather than invalidating every token in flight')]
    public function testRefusesToOverwrite(): void
    {
        self::generate(['algorithm' => 'ES256', '--name' => 'once', '--out' => self::$directory]);
        $tester = self::generate(['algorithm' => 'ES256', '--name' => 'once', '--out' => self::$directory]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('already exists', $tester->getDisplay());
    }

    #[TestDox('a shared secret is printed as an environment line, which is where the hmac source reads it')]
    public function testSharedSecret(): void
    {
        $tester = self::generate(['algorithm' => 'HS384', '--name' => 'api']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());

        $display = $tester->getDisplay();
        self::assertMatchesRegularExpression('/JWT_API_SECRET=(\S+)/', $display);

        self::assertSame(1, preg_match('/JWT_API_SECRET=(\S+)/', $display, $matches));
        // base64url of 48 random bytes: longer than the 48 RFC 8725 §3.5 asks
        // for HS384, because the value that reaches HmacKey is the encoded one.
        self::assertGreaterThanOrEqual(48, strlen($matches[1]));

        $configuration = self::snippet($display);
        self::assertSame('%env(JWT_API_SECRET)%', $configuration['keys']['api']['hmac']);
    }

    #[TestDox('a shared secret is not written to a file, because no key source reads one')]
    public function testSharedSecretRefusesOut(): void
    {
        $tester = self::generate(['algorithm' => 'HS256', '--out' => self::$directory]);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('belongs in the environment', $tester->getDisplay());
    }

    #[TestDox('EdDSA as a PEM says why there is none instead of generating something unusable')]
    public function testEdDsaHasNoPemForm(): void
    {
        $tester = self::generate(['algorithm' => 'EdDSA', '--format' => 'pem', '--out' => self::$directory]);

        self::assertSame(Command::INVALID, $tester->getStatusCode());
        self::assertStringContainsString('RFC 8037', $tester->getDisplay());
    }

    #[TestDox('an RSA size below what RFC 7518 requires is refused rather than generated')]
    public function testTooFewBits(): void
    {
        $tester = self::generate(['algorithm' => 'RS256', '--bits' => '1024', '--out' => self::$directory]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('RFC 7518', $tester->getDisplay());
    }

    #[TestDox('an algorithm the bundle does not sign with is named, with the ones it does')]
    public function testUnknownAlgorithm(): void
    {
        $tester = self::generate(['algorithm' => 'RS128', '--out' => self::$directory]);

        self::assertSame(Command::INVALID, $tester->getStatusCode());

        // The error block is wrapped to the terminal, so the list is asserted
        // by its ends rather than as one string.
        $display = $tester->getDisplay();
        self::assertStringContainsString('Unknown algorithm "RS128"', $display);
        self::assertStringContainsString('HS256', $display);
        self::assertStringContainsString('EdDSA', $display);
    }

    #[TestDox('a key generated without a kid says what rotation will need')]
    public function testKidlessKeySaysSo(): void
    {
        $tester = self::generate(['algorithm' => 'ES256', '--name' => 'anonymous', '--out' => self::$directory]);

        self::assertStringContainsString('rotation needs one', $tester->getDisplay());
        self::assertArrayNotHasKey('kid', self::snippet($tester->getDisplay())['keys']['anonymous']);
    }

    /**
     * @param array<string, string> $input
     */
    private static function generate(array $input): CommandTester
    {
        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => []]);

        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);

        $application = new Application($kernel);
        $application->setAutoExit(false);

        // Found by name through the console, not pulled out of the container:
        // a command the application cannot find is a command nobody can run,
        // whatever the service definition says.
        $tester = new CommandTester($application->find('jwt:key:generate'));
        $tester->execute($input);

        return $tester;
    }

    /**
     * The configuration block, read back out of the output the way a reader
     * would: select it, paste it, boot.
     *
     * @return array{keys: array<string, array<string, string>>}
     */
    private static function snippet(string $display): array
    {
        $lines = explode("\n", $display);
        $start = null;
        $block = [];

        foreach ($lines as $index => $line) {
            if (str_starts_with($line, 'medzuch_jwt:')) {
                $start = $index;
                $block[] = $line;

                continue;
            }

            if (null === $start) {
                continue;
            }

            if ('' === trim($line)) {
                break;
            }

            self::assertStringStartsWith(' ', $line, 'the block should be one indented run of lines');
            $block[] = $line;
        }

        self::assertNotNull($start, 'the command should print a configuration block');

        $parsed = Yaml::parse(implode("\n", $block));

        self::assertIsArray($parsed);
        self::assertIsArray($parsed['medzuch_jwt'] ?? null);
        self::assertIsArray($parsed['medzuch_jwt']['keys'] ?? null);

        /** @var array{keys: array<string, array<string, string>>} $configuration */
        $configuration = $parsed['medzuch_jwt'];

        return $configuration;
    }

    /**
     * @param array{keys: array<string, array<string, string>>} $configuration
     */
    private static function roundTrip(array $configuration, string $name, string $algorithm): string
    {
        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => $configuration + [
            'issuers' => ['default' => [
                'issuer' => 'https://issuer.test',
                'key' => $name,
                'client_id' => 'test-client',
                'audience' => 'https://api.test',
            ]],
            'consumers' => ['api' => [
                'issuer' => 'https://issuer.test',
                'audience' => 'https://api.test',
                'keys' => [$name],
                'allowed_algorithms' => [$algorithm],
            ]],
        ]]);

        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler->getUserBadgeFrom($issuer->issue('user-42')->value)->getUserIdentifier();
    }
}
