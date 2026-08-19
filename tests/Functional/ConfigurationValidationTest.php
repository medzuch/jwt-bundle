<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\ErrorHandler\ErrorHandler;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Every case here is a wiring mistake that would otherwise surface as a token
 * being rejected at runtime — with a message about the token, not about the
 * configuration that can never accept one.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class ConfigurationValidationTest extends KernelTestCase
{
    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    protected function tearDown(): void
    {
        parent::tearDown();

        $current = set_exception_handler(null);
        restore_exception_handler();

        if (is_array($current) && $current[0] instanceof ErrorHandler) {
            restore_exception_handler();
        }
    }

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('a consumer naming a key that does not exist fails at container build')]
    public function testUnknownKeyReference(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/names key "typo"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['keys' => ['typo']])],
        ]]);
    }

    #[TestDox('a consumer whose keys match none of its allowed algorithms fails at container build')]
    public function testConsumerThatCanNeverVerify(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/can never verify a token/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET, 'algorithm' => 'HS256']],
            'consumers' => ['api' => self::consumer(['allowed_algorithms' => ['RS256']])],
        ]]);
    }

    #[TestDox('two kid-less keys on one algorithm fail at container build (DEC-5)')]
    public function testIndistinguishableKeys(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/cannot say which one signed it/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['hmac' => self::SECRET],
                'previous' => ['hmac' => self::SECRET . '-old'],
            ],
            'consumers' => ['api' => self::consumer(['keys' => ['current', 'previous']])],
        ]]);
    }

    #[TestDox('the same two keys are fine once each carries a kid')]
    public function testDistinguishableKeysAreAccepted(): void
    {
        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['hmac' => self::SECRET, 'kid' => '2026-01'],
                'previous' => ['hmac' => self::SECRET . '-old', 'kid' => '2025-07'],
            ],
            'consumers' => ['api' => self::consumer(['keys' => ['current', 'previous']])],
        ]]);

        self::assertTrue(self::getContainer()->has('medzuch_jwt.handler.api'));
    }

    #[TestDox('leeway above the library ceiling fails at container build')]
    public function testLeewayCeiling(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['leeway' => 3600])],
        ]]);
    }

    #[TestDox('an unknown algorithm name fails at container build')]
    public function testUnknownAlgorithm(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['allowed_algorithms' => ['none']])],
        ]]);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function consumer(array $overrides = []): array
    {
        return $overrides + [
            'issuer' => 'https://issuer.test',
            'audience' => 'https://api.test',
            'keys' => ['default'],
            'allowed_algorithms' => ['HS256'],
        ];
    }
}
