<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Every case here is a wiring mistake that would otherwise surface as a token
 * being rejected at runtime — with a message about the token, not about the
 * configuration that can never accept one.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class ConfigurationValidationTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

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

    #[TestDox('an allowed algorithm with no key behind it fails at container build')]
    public function testConsumerThatCanNeverVerify(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/could never be verified/');

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

    #[TestDox('an algorithm on the allowlist with no key is refused even when another one is satisfied')]
    public function testPartiallySatisfiedAllowlist(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/allows RS256/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['allowed_algorithms' => ['HS256', 'RS256']])],
        ]]);
    }

    #[TestDox('two keys sharing a kid fail at container build')]
    public function testDuplicateKid(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/share the kid "2026-01"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['hmac' => self::SECRET, 'kid' => '2026-01'],
                'previous' => ['hmac' => self::SECRET . '-old', 'kid' => '2026-01'],
            ],
            'consumers' => ['api' => self::consumer(['keys' => ['current', 'previous']])],
        ]]);
    }

    #[TestDox('an empty kid is refused at container build rather than when the key is first used')]
    public function testEmptyKid(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET, 'kid' => '']],
            'consumers' => ['api' => self::consumer()],
        ]]);
    }

    #[TestDox('a map where a sequence is expected names the configuration key, not the token')]
    public function testAudienceAsMap(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/must be a sequence, not a map/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['audience' => ['primary' => 'https://api.test']])],
        ]]);
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

    #[TestDox('an issuer signing with a key that does not exist fails at container build')]
    public function testIssuerWithUnknownKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/signs with key "typo"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['key' => 'typo'])],
        ]]);
    }

    #[TestDox('a static claim using a registered claim name fails at container build, not at the first token')]
    public function testStaticClaimOverRegisteredName(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/registered claims/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['claims' => ['sub' => 'service-account']])],
        ]]);
    }

    #[TestDox('a static claim the library does not reserve is accepted')]
    public function testStaticClaimIsAccepted(): void
    {
        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['claims' => ['tenant' => 'acme']])],
        ]]);

        self::assertTrue(self::getContainer()->has('medzuch_jwt.issuer.default'));
    }

    #[TestDox('an issuer audience written as a map names the configuration key')]
    public function testIssuerAudienceAsMap(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/must be a sequence, not a map/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['audience' => ['primary' => 'https://api.test']])],
        ]]);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function issuer(array $overrides = []): array
    {
        return $overrides + [
            'issuer' => 'https://issuer.test',
            'key' => 'default',
            'client_id' => 'test-client',
            'audience' => 'https://api.test',
        ];
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
