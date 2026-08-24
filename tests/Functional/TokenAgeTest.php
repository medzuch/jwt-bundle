<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsVerification;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * A ceiling of this application's own on how old a token may be.
 *
 * Every token below is **inside its `exp`** — minted with an hour to live and
 * verified while it still has one. What varies is when it was issued, so a
 * refusal here can only be the age check: the library would accept all of them.
 */
#[CoversClass(AccessTokenHandler::class)]
#[CoversClass(RejectionReason::class)]
final class TokenAgeTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';
    private const NOW = '2026-01-01T00:00:00+00:00';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('a token older than the ceiling is refused, though its exp is still in the future')]
    public function testAnOldTokenIsRefused(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(maxTokenAge: 300)]);

        $failure = self::refuse(self::tokenIssued('-6 minutes'));

        self::assertInstanceOf(RejectedTokenException::class, $failure);
        self::assertSame(RejectionReason::TooOld, $failure->reason);

        // `too_old` and not `expired`: the issuer's lifetime has not run out,
        // this application's patience has, and a dashboard counting the two
        // together would be counting an issuer's generosity as an outage.
        self::assertCount(1, self::listener()->rejected);
        self::assertSame(RejectionReason::TooOld, self::listener()->rejected[0]->reason);
    }

    #[TestDox('a token inside the ceiling is accepted')]
    public function testAYoungTokenIsAccepted(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(maxTokenAge: 300)]);

        $badge = self::handler()->getUserBadgeFrom(self::tokenIssued('-4 minutes'));

        self::assertSame('user-42', $badge->getUserIdentifier());
        self::assertSame([], self::listener()->rejected);
    }

    #[TestDox('leeway widens the ceiling, as it widens every other dated check')]
    public function testLeewayWidensIt(): void
    {
        // Six minutes old against a five-minute ceiling: refused above, and
        // accepted here because ninety seconds of skew is allowed for.
        self::bootKernel(['medzuch_jwt' => self::configuration(maxTokenAge: 300, leeway: 90)]);

        $badge = self::handler()->getUserBadgeFrom(self::tokenIssued('-6 minutes'));

        self::assertSame('user-42', $badge->getUserIdentifier());
    }

    #[TestDox('nothing is asked about age unless a ceiling is configured')]
    public function testUnconfiguredAsksNothing(): void
    {
        self::bootKernel();

        // A day old and still inside its `exp`, which is the issuer's decision
        // and the only one there is when this consumer sets no ceiling.
        $badge = self::handler()->getUserBadgeFrom(self::tokenIssued('-1 day', livesFor: 'PT48H'));

        self::assertSame('user-42', $badge->getUserIdentifier());
        self::assertSame([], self::listener()->rejected);
    }

    #[TestDox('the ceiling is counted from the consumer clock, not the process clock')]
    public function testItReadsTheConfiguredClock(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(maxTokenAge: 300)]);

        // Minted four minutes before the frozen clock, so young; the process
        // clock is years away from it and would call this ancient.
        $token = self::tokenIssued('-4 minutes');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());

        // Two minutes later on the same clock it is over the ceiling, without
        // the token or the container changing.
        self::clock()->tick(new DateInterval('PT2M'));

        self::assertSame(RejectionReason::TooOld, self::refusalReason($token));
    }

    private static function refusalReason(string $token): RejectionReason
    {
        $failure = self::refuse($token);

        self::assertInstanceOf(RejectedTokenException::class, $failure);

        return $failure->reason;
    }

    private static function refuse(string $token): AuthenticationException
    {
        try {
            self::handler()->getUserBadgeFrom($token);
        } catch (AuthenticationException $failure) {
            return $failure;
        }

        self::fail('the token should have been refused');
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    private static function clock(): FrozenClock
    {
        $clock = self::getContainer()->get('test.frozen_clock');
        self::assertInstanceOf(FrozenClock::class, $clock);

        return $clock;
    }

    private static function listener(): RecordsVerification
    {
        $listener = self::getContainer()->get('test.verification_listener');
        self::assertInstanceOf(RecordsVerification::class, $listener);

        return $listener;
    }

    /**
     * @return array<string, mixed>
     */
    private static function configuration(?int $maxTokenAge = null, int $leeway = 0): array
    {
        $consumer = [
            'issuer' => self::ISSUER,
            'audience' => self::AUDIENCE,
            'keys' => ['default'],
            'allowed_algorithms' => ['HS256'],
        ];

        if (null !== $maxTokenAge) {
            $consumer['max_token_age'] = $maxTokenAge;
        }

        if (0 !== $leeway) {
            $consumer['leeway'] = $leeway;
        }

        return [
            // The same instant the tokens are dated against, so "six minutes
            // old" means six minutes to the consumer as well as to the mint.
            'clock' => 'test.frozen_clock',
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => $consumer],
        ];
    }

    /**
     * A token issued at some offset from the frozen instant, with a lifetime
     * long enough that `exp` is never what refuses it.
     */
    private static function tokenIssued(string $offset, string $livesFor = 'PT1H'): string
    {
        $issuedAt = (new DateTimeImmutable(self::NOW))->modify($offset);

        self::assertNotFalse($issuedAt);

        $profile = AccessTokenProfile::issuer(
            self::ISSUER,
            new Hs256(),
            HmacKey::fromBinary(self::SECRET, 'HS256'),
            FrozenClock::at($issuedAt->format(DateTimeImmutable::ATOM)),
        );

        return (string) $profile->issue()
            ->subject('user-42')
            ->audience(self::AUDIENCE)
            ->clientId('test-client')
            ->expiresIn(new DateInterval($livesFor))
            ->build();
    }
}
