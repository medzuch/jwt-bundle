<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Command\DumpJwksCommand;
use Medzuch\JwtBundle\Jwks\JwksController;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Exception\CommandNotFoundException;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The document the command prints is the document the endpoint serves.
 *
 * Asserted by comparing them rather than by describing both: the command exists
 * so an application can publish its keys without the route, and a dump that had
 * drifted from what K4 serves would be worse than no command at all.
 */
#[CoversClass(DumpJwksCommand::class)]
final class DumpJwksCommandTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('--compact prints exactly what the endpoint serves')]
    public function testCompactMatchesTheEndpoint(): void
    {
        $tester = self::dump(['--compact' => true]);

        $controller = self::getContainer()->get('medzuch_jwt.jwks_controller');
        self::assertInstanceOf(JwksController::class, $controller);

        $served = $controller(Request::create('/.well-known/jwks.json'))->getContent();

        self::assertIsString($served);
        // The whole output, not a trimmed version of it: byte for byte is the
        // promise, and trim() would forgive a trailing newline — the one byte
        // that makes a hash of the dumped file disagree with the endpoint's
        // ETag for the same keys.
        self::assertSame($served, $tester->getDisplay());
    }

    #[TestDox('the default is indented, and is the same document')]
    public function testDefaultIsIndented(): void
    {
        $tester = self::dump([]);
        $display = $tester->getDisplay();

        self::assertStringContainsString("\n    ", $display, 'a console is read by people');

        $printed = json_decode($display, true, flags: \JSON_THROW_ON_ERROR);
        $compact = json_decode(self::dump(['--compact' => true])->getDisplay(), true, flags: \JSON_THROW_ON_ERROR);

        self::assertSame($compact, $printed);
    }

    #[TestDox('what it prints is a key set of public halves, one per configured key')]
    public function testPrintsThePublicHalves(): void
    {
        $document = json_decode(self::dump([])->getDisplay(), true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($document);
        self::assertIsArray($document['keys'] ?? null);
        self::assertCount(2, $document['keys']);

        foreach ($document['keys'] as $jwk) {
            self::assertIsArray($jwk);
            // The private halves of every family this bundle can publish, and
            // the symmetric secret that must never appear at all.
            foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as $private) {
                self::assertArrayNotHasKey($private, $jwk, 'a published JWK carries no private material');
            }
        }
    }

    #[TestDox('an application that publishes nothing is not offered a command that would print nothing')]
    public function testAbsentWithoutPublishedKeys(): void
    {
        // Keys configured and none of them published, which is what a resource
        // server looks like — and the case the registration predicate is really
        // about. An application with no keys at all would be absent whatever
        // that predicate said.
        $configuration = self::configuration();
        unset($configuration['jwks']);

        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => $configuration]);

        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);

        $this->expectException(CommandNotFoundException::class);
        (new Application($kernel))->find('jwt:jwks:dump');
    }

    /**
     * @param array<string, mixed> $input
     */
    private static function dump(array $input): CommandTester
    {
        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $kernel = self::$kernel;
        self::assertInstanceOf(KernelInterface::class, $kernel);

        $application = new Application($kernel);
        $application->setAutoExit(false);

        $tester = new CommandTester($application->find('jwt:jwks:dump'));
        $tester->execute($input);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());

        return $tester;
    }

    /** @var array<string, mixed>|null */
    private static ?array $configuration = null;

    /**
     * Kept, because `ed25519Jwks()` mints a fresh pair on every call and two
     * cases here compare one run of the command against another. Two documents
     * that differ because the fixture changed under them would fail for a
     * reason that has nothing to do with the command.
     *
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        if (null !== self::$configuration) {
            return self::$configuration;
        }

        $rsa = self::keypair('rsa');
        $ed = self::ed25519Jwks('ed-2026');

        return self::$configuration = [
            'keys' => [
                // Both halves, so the private-material scan below can fail:
                // with only a public half configured there is no signing key in
                // the container for the set to be built from by mistake.
                //
                // The `kid` is awkward on purpose. `<` and `>` are escaped by
                // JsonResponse and left alone by a bare json_encode(), and `/`
                // is escaped by both but not by JSON_UNESCAPED_SLASHES — which
                // is the flag this command first reached for. Between them the
                // parity test fails for either mistake; a slash alone catches
                // only the second.
                'rsa' => [
                    'pem_private' => $rsa['private'],
                    'pem_public' => $rsa['public'],
                    'algorithm' => 'RS256',
                    'kid' => 'rsa/<2026>',
                ],
                // Both halves here too, so the scan runs against a container
                // that really holds signing material for every key in the set.
                'ed' => [
                    'jwk_private' => $ed['private'],
                    'jwk_public' => $ed['public'],
                    'algorithm' => 'EdDSA',
                    'kid' => 'ed-2026',
                ],
            ],
            'jwks' => ['keys' => ['rsa', 'ed']],
        ];
    }
}
