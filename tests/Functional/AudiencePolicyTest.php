<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * How much of a token's `aud` has to be ours.
 *
 * The default is what RFC 7519 §4.1.3 says: a token naming us is for us,
 * whoever else it names. `exclusive` is the posture RFC 9068 §3 asks of an
 * access token — a token minted for several services is valid at each of them,
 * so it only has to leak from the least careful one to arrive here.
 */
#[CoversClass(AccessTokenHandler::class)]
final class AudiencePolicyTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    private const OURS = 'https://api.test';

    private const THEIRS = 'https://reports.test';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('by default a token addressed to us among others is accepted')]
    public function testAnyAcceptsASharedToken(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $token = self::issuer()->issue('user-42', audience: [self::OURS, self::THEIRS]);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('an exclusive consumer refuses a token minted for another service as well')]
    public function testExclusiveRefusesASharedToken(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration('exclusive')]);

        $token = self::issuer()->issue('user-42', audience: [self::OURS, self::THEIRS]);

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessageMatches('/addressed to "https:\/\/reports\.test" as well/');

        self::handler()->getUserBadgeFrom($token->value);
    }

    #[TestDox('an exclusive consumer accepts a token minted for it alone')]
    public function testExclusiveAcceptsItsOwnToken(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration('exclusive')]);

        // The issuer mints for both services by default, which is the case the
        // policy exists for; here it is asked for a token addressed to us.
        $token = self::issuer()->issue('user-42', audience: [self::OURS]);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('a consumer answering to two names accepts a token naming either of them')]
    public function testExclusiveAllowsEveryConfiguredName(): void
    {
        // Exclusivity is about audiences we did not configure, not about the
        // token naming all of ours: an application answering to two names is
        // addressed by either.
        self::bootKernel(['medzuch_jwt' => self::configuration('exclusive', [self::OURS, 'https://api.internal.test'])]);

        $token = self::issuer()->issue('user-42', audience: ['https://api.internal.test']);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
    }

    #[TestDox('an unknown audience policy fails at container build')]
    public function testUnknownPolicy(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => self::configuration('strict-ish')]);
    }

    private static function issuer(): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * @param list<string> $audience names this consumer answers to
     *
     * @return array<string, mixed>
     */
    private static function configuration(?string $policy = null, array $audience = [self::OURS]): array
    {
        $consumer = [
            'issuer' => 'https://issuer.test',
            'audience' => $audience,
            'keys' => ['default'],
            'allowed_algorithms' => ['HS256'],
        ];

        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => [
                'default' => [
                    'issuer' => 'https://issuer.test',
                    'key' => 'default',
                    'client_id' => 'test-client',
                    'audience' => [self::OURS, self::THEIRS],
                ],
            ],
            'consumers' => ['api' => null === $policy ? $consumer : $consumer + ['audience_policy' => $policy]],
        ];
    }
}
