<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\CollectingLogger;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Exercises the wiring end to end: configuration in, a working consumer out.
 *
 * Tokens are minted with the library directly rather than through the bundle,
 * so a fault in the issuing side cannot make the verifying side look correct.
 */
#[CoversClass(AccessTokenHandler::class)]
final class AccessTokenHandlerTest extends KernelTestCase
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

    #[TestDox('a valid token becomes a user badge carrying the subject')]
    public function testValidTokenYieldsUserBadge(): void
    {
        self::bootKernel();

        $badge = self::handler()->getUserBadgeFrom(self::token());

        self::assertSame('user-42', $badge->getUserIdentifier());
    }

    #[TestDox('a token signed with another secret is refused')]
    public function testWrongSignatureIsRefused(): void
    {
        self::bootKernel();

        $this->expectException(BadCredentialsException::class);

        self::handler()->getUserBadgeFrom(self::token(secret: 'a-different-secret-of-32-bytes-min!!!'));
    }

    #[TestDox('a token minted for another audience is refused')]
    public function testWrongAudienceIsRefused(): void
    {
        self::bootKernel();

        $this->expectException(BadCredentialsException::class);

        self::handler()->getUserBadgeFrom(self::token(audience: 'https://other.test'));
    }

    #[TestDox('an expired token is refused when no leeway is configured')]
    public function testExpiredTokenIsRefused(): void
    {
        self::bootKernel();

        $this->expectException(BadCredentialsException::class);

        self::handler()->getUserBadgeFrom(self::token(expiresAt: new DateTimeImmutable('-1 minute')));
    }

    #[TestDox('the identity claim is configurable, so the badge need not come from sub')]
    public function testIdentityClaimIsConfigurable(): void
    {
        $configuration = self::configuration();
        $configuration['consumers']['api']['user'] = ['identity_claim' => 'email'];

        self::bootKernel(['medzuch_jwt' => $configuration]);

        $token = self::token(extraClaims: ['email' => 'user@example.test']);

        self::assertSame('user@example.test', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    #[TestDox('a token without the identity claim is refused rather than yielding an empty badge')]
    public function testMissingIdentityClaimIsRefused(): void
    {
        $configuration = self::configuration();
        $configuration['consumers']['api']['user'] = ['identity_claim' => 'email'];

        self::bootKernel(['medzuch_jwt' => $configuration]);

        $this->expectException(BadCredentialsException::class);

        self::handler()->getUserBadgeFrom(self::token());
    }

    #[TestDox('a configured logger receives the library\'s account of a refusal')]
    public function testRefusalIsLogged(): void
    {
        $configuration = self::configuration();
        $configuration['logger'] = 'test.logger';

        self::bootKernel(['medzuch_jwt' => $configuration]);

        try {
            self::handler()->getUserBadgeFrom(self::token(secret: 'a-different-secret-of-32-bytes-min!!!'));
        } catch (BadCredentialsException) {
            // The refusal is the point; what it left in the log is the assertion.
        }

        $logger = self::getContainer()->get('test.logger');
        self::assertInstanceOf(CollectingLogger::class, $logger);
        self::assertNotSame([], $logger->records, 'configuring `logger` must reach the library\'s security log');
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function configuration(): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => [
                'api' => [
                    'issuer' => self::ISSUER,
                    'audience' => self::AUDIENCE,
                    'keys' => ['default'],
                    'allowed_algorithms' => ['HS256'],
                ],
            ],
        ];
    }

    /**
     * @param array<string, mixed> $extraClaims
     */
    private static function token(
        string $secret = self::SECRET,
        string $audience = self::AUDIENCE,
        ?DateTimeImmutable $expiresAt = null,
        array $extraClaims = [],
    ): string {
        $profile = AccessTokenProfile::issuer(
            self::ISSUER,
            new Hs256(),
            HmacKey::fromBinary($secret, 'HS256'),
        );

        $builder = $profile->issue()
            ->subject('user-42')
            ->audience($audience)
            ->clientId('test-client');

        $builder = null === $expiresAt
            ? $builder->expiresIn(new DateInterval('PT5M'))
            : $builder->expiresAt($expiresAt);

        foreach ($extraClaims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return (string) $builder->build();
    }
}
