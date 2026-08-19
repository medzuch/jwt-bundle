<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Primitives\SystemClock;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;
use Medzuch\JwtBundle\MedzuchJwtBundle;

#[CoversClass(MedzuchJwtBundle::class)]
final class BundleBootTest extends KernelTestCase
{
    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('the bundle compiles into a container with no configuration at all')]
    public function testBootsWithoutConfiguration(): void
    {
        self::bootKernel();

        $clock = self::getContainer()->get('medzuch_jwt.clock');

        self::assertInstanceOf(SystemClock::class, $clock);
    }

    #[TestDox('a configured clock replaces the default rather than sitting beside it')]
    public function testConfiguredClockReplacesTheDefault(): void
    {
        self::bootKernel(['medzuch_jwt' => ['clock' => 'test.frozen_clock']]);

        $clock = self::getContainer()->get('medzuch_jwt.clock');

        self::assertInstanceOf(FrozenClock::class, $clock);
        self::assertSame(
            '2026-01-01T00:00:00+00:00',
            $clock->now()->format('c'),
            'the alias must resolve to the application service, not to a second SystemClock',
        );
    }

    #[TestDox('an unknown configuration key fails at container build, not at the first request')]
    public function testUnknownConfigurationKeyIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => ['no_such_key' => true]]);
    }
}
