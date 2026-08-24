<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Holds the two tables an application actually names to the container.
 *
 * `BackwardCompatibilityTest` holds the class table, which is the surface a new
 * file breaks quietly. This one holds the other two, which are the surface a
 * `security.yaml` and a deploy script are written against: a renamed service-id
 * prefix or a command that stopped being registered would leave the policy
 * silently false exactly where it is most read.
 *
 * The ids are patterns — `medzuch_jwt.handler.<consumer>` — so the kernel below
 * configures one of everything under the names the placeholders are replaced
 * with, and every row is then an id the container has to answer with the type
 * its own row names.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class PublicSurfaceTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const POLICY = __DIR__ . '/../../BACKWARD-COMPATIBILITY.md';

    /**
     * The names the policy's placeholders stand for, as this kernel configures
     * them.
     */
    private const NAMES = [
        '<consumer>' => 'api',
        '<issuer>' => 'api',
        '<registration>' => 'partner',
        '<extractor>' => 'spa',
        '<key>' => 'signer',
    ];

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $ec = self::keypair('ec', ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        return new TestKernel([
            'keys' => [
                // A shared secret is both halves at once, so one entry
                // advertises the `.signing` and `.verification` rows together.
                'signer' => ['hmac' => 'a-secret-long-enough-for-hs256-to-accept', 'algorithm' => 'HS256'],
                // A secret cannot be published — its JWK carries the secret —
                // so the JWK Set rows need a key with a public half of its own.
                'published' => ['pem_public' => $ec['public'], 'algorithm' => 'ES256', 'kid' => 'ec-2026'],
            ],
            'token_extractors' => ['spa' => ['cookie' => '__Host-jwt']],
            'issuers' => [
                'api' => ['issuer' => 'https://api.test', 'key' => 'signer', 'client_id' => 'api', 'audience' => 'https://api.test'],
            ],
            'consumers' => [
                'api' => [
                    'issuer' => 'https://api.test',
                    'audience' => 'https://api.test',
                    'keys' => ['signer'],
                    'allowed_algorithms' => ['HS256'],
                    'denylist' => ['cache' => 'test.cache'],
                ],
            ],
            'id_tokens' => [
                'partner' => ['issuer' => 'https://idp.test', 'client_id' => 'client', 'keys' => ['signer'], 'allowed_algorithms' => ['HS256']],
            ],
            'jwks' => ['keys' => ['published']],
        ]);
    }

    #[TestDox('every service id the policy promises resolves, to the type its row names')]
    public function testPromisedServiceIdsResolve(): void
    {
        $rows = self::table('Id', 'Answers');

        self::assertGreaterThan(5, count($rows), 'the policy should promise service ids');

        $container = self::getContainer();

        foreach ($rows as $id => $type) {
            $resolved = str_replace(array_keys(self::NAMES), array_values(self::NAMES), $id);

            self::assertTrue($container->has($resolved), sprintf('the policy promises "%s", which this container does not have', $id));

            $service = $container->get($resolved);

            if ('callable' === $type) {
                self::assertIsCallable($service, sprintf('the policy says "%s" is callable', $id));

                continue;
            }

            self::assertTrue(
                interface_exists($type) || class_exists($type),
                sprintf('the policy says "%s" answers %s, which is not a type', $id, $type),
            );

            self::assertInstanceOf($type, $service, sprintf('the policy says "%s" answers %s', $id, $type));
        }
    }

    #[TestDox('every command the policy promises is registered, with the options it calls stable')]
    public function testPromisedCommandsAreRegistered(): void
    {
        // The options the policy names as the ones a script may rely on, which
        // is a shorter list than the commands have and the only part of what
        // they print that is promised.
        $scriptable = [
            'jwt:token:create' => 'raw',
            'jwt:jwks:dump' => 'compact',
            'jwt:config:check' => 'skip-remote',
        ];

        $rows = self::table('Command', 'Registered');

        self::assertCount(5, $rows, 'the policy should promise five commands');

        $application = new Application(self::$kernel ?? self::bootKernel());

        foreach (array_keys($rows) as $name) {
            self::assertTrue($application->has($name), sprintf('the policy promises "%s", which is not registered', $name));

            if (!isset($scriptable[$name])) {
                continue;
            }

            self::assertTrue(
                $application->get($name)->getDefinition()->hasOption($scriptable[$name]),
                sprintf('the policy says "%s --%s" is what a script may rely on', $name, $scriptable[$name]),
            );
        }
    }

    /**
     * The first two cells of every row of the table with these two headings.
     *
     * The policy is written for a reader, so the parsing is deliberately narrow:
     * a heading row naming both columns, then rows whose first two cells are
     * each a single backticked value. A row that stops matching that shape
     * disappears from the check, which is why both cases assert how many rows
     * they found.
     *
     * @return array<string, string>
     */
    private static function table(string $first, string $second): array
    {
        $policy = file_get_contents(self::POLICY);

        if (false === $policy) {
            throw new RuntimeException('BACKWARD-COMPATIBILITY.md is unreadable');
        }

        $heading = sprintf('| %s | %s |', $first, $second);
        $start = strpos($policy, $heading);

        if (false === $start) {
            throw new RuntimeException(sprintf('BACKWARD-COMPATIBILITY.md has no "%s" table', $heading));
        }

        $end = strpos($policy, "\n\n", $start);
        $body = substr($policy, $start, false === $end ? null : $end - $start);

        preg_match_all('/^\| `([^`]+)` \| `?([^`|]+?)`? \|/m', $body, $matches, \PREG_SET_ORDER);

        $rows = [];

        foreach ($matches as $match) {
            $rows[$match[1]] = trim($match[2]);
        }

        return $rows;
    }
}
