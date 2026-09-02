<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Refresh\RefreshToken;
use Medzuch\JwtBundle\Refresh\RefreshTokenGenerator;
use Medzuch\JwtBundle\Refresh\RefreshTokenRecord;
use Medzuch\JwtBundle\Tests\Functional\App\InMemoryRefreshTokenStore;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The refresh-token contract (I9) and the generator that fills it.
 *
 * What is under test is a shape, not a feature: this bundle stores nothing, so
 * the store here is a test double implementing the published interface. That
 * double is the assertion — if the rotation flow below cannot be written
 * against the interface as it stands, the interface is wrong.
 *
 * The flow the file walks through is the one OAuth 2.1 §6.1 asks for: mint,
 * store the hash, spend once, mint the next, and treat a second presentation
 * of a spent token as a reason to end every session the subject has.
 */
#[CoversClass(RefreshTokenGenerator::class)]
#[CoversClass(RefreshToken::class)]
#[CoversClass(RefreshTokenRecord::class)]
final class RefreshTokenContractTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const SUBJECT = 'user-42';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('the generator is a service, and autowirable by type')]
    public function testTheGeneratorIsWired(): void
    {
        self::bootKernel();

        self::assertInstanceOf(RefreshTokenGenerator::class, self::getContainer()->get('medzuch_jwt.refresh_token_generator'));
        self::assertTrue(self::getContainer()->has(RefreshTokenGenerator::class));
    }

    #[TestDox('a minted token hands the client a value and the store a hash of it')]
    public function testTheTwoHalves(): void
    {
        $token = self::generator()->generate(new DateInterval('P30D'));

        self::assertNotSame($token->value, $token->hash);
        self::assertSame(RefreshToken::hashOf($token->value), $token->hash);
        // 32 bytes of base64url without padding, and nothing that needs
        // escaping in a URL, a header or a JSON string.
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $token->value);
    }

    #[TestDox('two tokens minted in the same second are different tokens')]
    public function testTokensAreUnique(): void
    {
        $generator = self::generator();

        $minted = [];

        for ($i = 0; $i < 50; ++$i) {
            $minted[] = $generator->generate(new DateInterval('P30D'))->value;
        }

        self::assertCount(50, array_unique($minted));
    }

    #[TestDox('a lifetime that ends before it starts is refused at minting')]
    public function testALifetimeMustBePositive(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/ends after it starts/');

        self::generator()->generate(new DateInterval('PT0S'));
    }

    #[TestDox('the whole rotation: mint, store, spend once, mint the next')]
    public function testRotation(): void
    {
        $now = FrozenClock::at('2026-09-02T12:00:00+00:00');
        $generator = self::generator($now);
        $store = new InMemoryRefreshTokenStore();

        $first = $generator->generate(new DateInterval('P30D'));
        $store->store($first, self::SUBJECT);

        // What the store keeps is the hash. The value went to the client and
        // exists nowhere on this side.
        self::assertFalse($store->holdsPlaintext($first->value));

        $record = $store->consume($first->value);

        self::assertInstanceOf(RefreshTokenRecord::class, $record);
        self::assertSame(self::SUBJECT, $record->subject);
        self::assertTrue($record->isUsable($now));

        $second = $generator->generate(new DateInterval('P30D'));
        $store->store($second, $record->subject);

        self::assertNotSame($first->value, $second->value);
    }

    #[TestDox('a token presented twice comes back spent, which is not the same as unknown')]
    public function testReuseIsDistinguishableFromNonsense(): void
    {
        $now = FrozenClock::at('2026-09-02T12:00:00+00:00');
        $store = new InMemoryRefreshTokenStore();

        $token = self::generator($now)->generate(new DateInterval('P30D'));
        $store->store($token, self::SUBJECT);

        $store->consume($token->value);
        $replay = $store->consume($token->value);

        self::assertInstanceOf(RefreshTokenRecord::class, $replay);
        self::assertTrue($replay->alreadyUsed);
        self::assertFalse($replay->isUsable($now));

        // The distinction the contract exists for: a string nobody ever issued
        // is silence, a real token spent twice is a report.
        self::assertNull($store->consume('a-string-nobody-ever-issued'));
    }

    #[TestDox('reacting to a replay ends every session the subject has')]
    public function testTheFamilyCanBeKilled(): void
    {
        $now = FrozenClock::at('2026-09-02T12:00:00+00:00');
        $generator = self::generator($now);
        $store = new InMemoryRefreshTokenStore();

        $stolen = $generator->generate(new DateInterval('P30D'));
        $store->store($stolen, self::SUBJECT);
        $store->store($generator->generate(new DateInterval('P30D')), self::SUBJECT);
        $store->store($generator->generate(new DateInterval('P30D')), 'somebody-else');

        $store->consume($stolen->value);
        $replay = $store->consume($stolen->value);

        self::assertInstanceOf(RefreshTokenRecord::class, $replay);
        self::assertTrue($replay->alreadyUsed);

        $store->revokeAllFor($replay->subject);

        self::assertSame(0, $store->countFor(self::SUBJECT));
        // One subject's bad day is not everybody's.
        self::assertSame(1, $store->countFor('somebody-else'));
    }

    #[TestDox('an expired token is refused even where the store still holds it')]
    public function testExpiry(): void
    {
        $minted = FrozenClock::at('2026-09-02T12:00:00+00:00');
        $store = new InMemoryRefreshTokenStore();

        $token = self::generator($minted)->generate(new DateInterval('PT300S'));
        $store->store($token, self::SUBJECT);

        $record = $store->consume($token->value);

        self::assertInstanceOf(RefreshTokenRecord::class, $record);
        self::assertTrue($record->isUsable($minted));
        self::assertFalse($record->isUsable(new DateTimeImmutable('2026-09-02T12:05:01+00:00')));
        self::assertTrue($record->isExpired(FrozenClock::at('2026-09-02T13:00:00+00:00')));
    }

    #[TestDox('an empty presentation is refused rather than hashed into a lookup')]
    public function testEmptyPresentation(): void
    {
        $this->expectException(InvalidArgumentException::class);

        RefreshToken::hashOf('');
    }

    private static function generator(?FrozenClock $clock = null): RefreshTokenGenerator
    {
        if (null === $clock) {
            self::bootKernel();
            $generator = self::getContainer()->get('medzuch_jwt.refresh_token_generator');
            self::assertInstanceOf(RefreshTokenGenerator::class, $generator);

            return $generator;
        }

        return new RefreshTokenGenerator($clock);
    }
}
