<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\CollectingLogger;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * What level each kind of diagnostic is emitted at.
 *
 * The library decides the level and the application's logger decides whether
 * to record it, so the only thing worth asserting here is that a configured
 * level reaches the library — which means reading the level off what was
 * actually logged rather than off the container.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class LogLevelsTest extends KernelTestCase
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

    #[TestDox('unconfigured, the library keeps its own defaults')]
    public function testTheLibraryDefaults(): void
    {
        self::bootKernel();

        self::handler()->getUserBadgeFrom(self::token());
        self::refuse(self::token(expiresAt: new DateTimeImmutable('-1 hour')));

        // `debug` for an accepted token and `notice` for a claim refused: the
        // library's, not this bundle's, and asserted so that a change to them
        // shows up here rather than in somebody's log volume.
        self::assertSame('debug', self::levelOf('accepted'));
        self::assertSame('notice', self::levelOf('rejected'));
    }

    #[TestDox('a configured level is what the library emits at')]
    public function testAConfiguredLevelReachesTheLibrary(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration([
            'accepted' => 'info',
            'claim_rejected' => 'warning',
        ])]);

        self::handler()->getUserBadgeFrom(self::token());
        self::refuse(self::token(expiresAt: new DateTimeImmutable('-1 hour')));

        self::assertSame('info', self::levelOf('accepted'));
        self::assertSame('warning', self::levelOf('rejected'));
    }

    #[TestDox('a category left alone keeps its default beside one that was set')]
    public function testOneCategoryAtATime(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['claim_rejected' => 'error'])]);

        self::handler()->getUserBadgeFrom(self::token());
        self::refuse(self::token(expiresAt: new DateTimeImmutable('-1 hour')));

        // Named arguments are why: setting one category must not restate the
        // other six at whatever this bundle believed their defaults were.
        self::assertSame('error', self::levelOf('rejected'));
        self::assertSame('debug', self::levelOf('accepted'));
    }

    #[TestDox('a level that is not a PSR-3 one fails at container build')]
    public function testAnUnknownLevelIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('must be one of the eight PSR-3 levels');

        self::bootKernel(['medzuch_jwt' => self::configuration(['accepted' => 'chatty'])]);
    }

    #[TestDox('levels without a logger fail at container build')]
    public function testLevelsNeedALogger(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('nothing would emit at those levels');

        $configuration = self::configuration(['accepted' => 'info']);
        unset($configuration['logger']);

        self::bootKernel(['medzuch_jwt' => $configuration]);
    }

    /**
     * The level of the first record whose message names an outcome.
     */
    private static function levelOf(string $outcome): string
    {
        $logger = self::getContainer()->get('test.logger');
        self::assertInstanceOf(CollectingLogger::class, $logger);

        foreach ($logger->records as $record) {
            if (str_contains(strtolower($record['message']), $outcome)) {
                return $record['level'];
            }
        }

        self::fail(sprintf('nothing was logged about a token being %s; got %s', $outcome, json_encode($logger->records)));
    }

    private static function refuse(string $token): void
    {
        try {
            self::handler()->getUserBadgeFrom($token);
        } catch (AuthenticationException) {
            return;
        }

        self::fail('the token should have been refused');
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * @param array<string, string> $levels
     *
     * @return array<string, mixed>
     */
    private static function configuration(array $levels = []): array
    {
        $configuration = [
            'logger' => 'test.logger',
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => [
                'issuer' => self::ISSUER,
                'audience' => self::AUDIENCE,
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
            ]],
        ];

        if ([] !== $levels) {
            $configuration['log_levels'] = $levels;
        }

        return $configuration;
    }

    private static function token(?DateTimeImmutable $expiresAt = null): string
    {
        $builder = AccessTokenProfile::issuer(self::ISSUER, new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'))
            ->issue()
            ->subject('user-42')
            ->audience(self::AUDIENCE)
            ->clientId('test-client');

        return (string) (null === $expiresAt
            ? $builder->expiresIn(new DateInterval('PT5M'))
            : $builder->expiresAt($expiresAt))->build();
    }
}
