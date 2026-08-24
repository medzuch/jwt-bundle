<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\DependencyInjection\CheckConfiguredServicesPass;
use Medzuch\JwtBundle\Tests\Functional\App\BareKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * A configuration that names a service nobody has is refused while the
 * container is built, and the message says which key named it.
 *
 * The kernel here is deliberately bare — no bundle service made public, no
 * application services registered. Making the bundle's services public, which
 * every other functional kernel does so a test can reach them, forces Symfony
 * to resolve aliases it would otherwise drop: `clock: 'app.nope'` fails under
 * that kernel and would have looked like coverage this bundle did not have.
 */
#[CoversClass(CheckConfiguredServicesPass::class)]
final class ConfiguredServicesTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const CONSUMER = [
        'issuer' => 'https://api.test',
        'audience' => 'https://api.test',
        'keys' => ['signer'],
        'allowed_algorithms' => ['HS256'],
    ];

    private const KEYS = ['signer' => ['hmac' => 'a-secret-long-enough-for-hs256-to-take', 'algorithm' => 'HS256']];

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new BareKernel(is_array($config) ? $config : []);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function namedServices(): iterable
    {
        yield 'clock' => [
            ['clock' => 'app.no_such_clock'],
            'medzuch_jwt.clock',
            'app.no_such_clock',
        ];

        // The one that compiled clean before this pass existed: with no
        // consumer, issuer, ID token or remote set, nothing references the
        // logger, so nothing noticed it was not there.
        yield 'logger nothing references' => [
            ['logger' => 'app.no_such_logger'],
            'medzuch_jwt.logger',
            'app.no_such_logger',
        ];

        yield 'logger a consumer uses' => [
            ['logger' => 'app.no_such_logger', 'keys' => self::KEYS, 'consumers' => ['api' => self::CONSUMER]],
            'medzuch_jwt.logger',
            'app.no_such_logger',
        ];

        yield 'denylist service' => [
            ['keys' => self::KEYS, 'consumers' => ['api' => self::CONSUMER + ['denylist' => ['service' => 'app.no_such_denylist']]]],
            'medzuch_jwt.consumers.api.denylist.service',
            'app.no_such_denylist',
        ];

        yield 'denylist cache' => [
            ['keys' => self::KEYS, 'consumers' => ['api' => self::CONSUMER + ['denylist' => ['cache' => 'app.no_such_cache']]]],
            'medzuch_jwt.consumers.api.denylist.cache',
            'app.no_such_cache',
        ];

        yield 'denylist cache pool' => [
            ['keys' => self::KEYS, 'consumers' => ['api' => self::CONSUMER + ['denylist' => ['cache_pool' => 'app.no_such_pool']]]],
            'medzuch_jwt.consumers.api.denylist.cache_pool',
            'app.no_such_pool',
        ];

        yield 'user factory' => [
            ['keys' => self::KEYS, 'consumers' => ['api' => self::CONSUMER + ['user' => ['mode' => 'custom', 'factory' => 'App\\NoSuchFactory']]]],
            'medzuch_jwt.consumers.api.user.factory',
            'App\\NoSuchFactory',
        ];

        yield 'remote jwks http client' => [
            ['remote_jwks' => ['idp' => ['uri' => 'https://idp.test/jwks', 'http_client' => 'app.no_such_client']]],
            'medzuch_jwt.remote_jwks.idp.http_client',
            'app.no_such_client',
        ];

        yield 'remote jwks request factory' => [
            ['remote_jwks' => ['idp' => ['uri' => 'https://idp.test/jwks', 'http_client' => 'test.http_client', 'request_factory' => 'app.no_such_factory']]],
            'medzuch_jwt.remote_jwks.idp.request_factory',
            'app.no_such_factory',
        ];

        yield 'remote jwks cache' => [
            ['remote_jwks' => ['idp' => ['uri' => 'https://idp.test/jwks', 'http_client' => 'test.http_client', 'cache' => 'app.no_such_cache']]],
            'medzuch_jwt.remote_jwks.idp.cache',
            'app.no_such_cache',
        ];
    }

    /**
     * @param array<string, mixed> $configuration
     */
    #[DataProvider('namedServices')]
    #[TestDox('$path naming a service nobody has is refused while the container is built')]
    public function testAServiceNobodyHasIsRefused(array $configuration, string $path, string $id): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(sprintf('%s names "%s"', $path, $id));

        self::bootKernel(['medzuch_jwt' => $configuration]);
    }

    #[TestDox('a default nobody enabled is named as the default it is')]
    public function testADefaultSaysItIsOne(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('medzuch_jwt.remote_jwks.idp.http_client names "psr18.http_client" — the default.');

        self::bootKernel(['medzuch_jwt' => ['remote_jwks' => ['idp' => ['uri' => 'https://idp.test/jwks']]]]);
    }

    #[TestDox('every mistake is named at once, not the first of them')]
    public function testAllOfThemAtOnce(): void
    {
        try {
            self::bootKernel(['medzuch_jwt' => [
                'clock' => 'app.no_such_clock',
                'logger' => 'app.no_such_logger',
                'keys' => self::KEYS,
                'consumers' => ['api' => self::CONSUMER + ['user' => ['mode' => 'custom', 'factory' => 'App\\NoSuchFactory']]],
            ]]);

            self::fail('the container should not have compiled');
        } catch (InvalidConfigurationException $e) {
            self::assertStringContainsString('medzuch_jwt.clock names "app.no_such_clock"', $e->getMessage());
            self::assertStringContainsString('medzuch_jwt.logger names "app.no_such_logger"', $e->getMessage());
            self::assertStringContainsString('medzuch_jwt.consumers.api.user.factory names "App\\NoSuchFactory"', $e->getMessage());
            self::assertStringContainsString('services this application does not have', $e->getMessage());
        }
    }

    #[TestDox('a configuration naming services that exist compiles, and leaves no parameter behind')]
    public function testWhatItLeavesBehind(): void
    {
        self::bootKernel(['medzuch_jwt' => [
            'clock' => 'test.clock',
            'keys' => self::KEYS,
            'consumers' => ['api' => self::CONSUMER + ['denylist' => ['cache' => 'test.cache']]],
        ]]);

        // The parameter is how the extension reaches the pass. A compiled
        // container still holding it would be this check leaking into every
        // application's `debug:container`.
        self::assertFalse(self::getContainer()->hasParameter(CheckConfiguredServicesPass::CONFIGURED));
    }
}
