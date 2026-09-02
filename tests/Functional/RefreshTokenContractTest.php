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
 * The flow the file walks through is the one RFC 9700 §4.14.2 describes: mint,
 * store the hash, spend once, mint the next — and, when a spent token is
 * presented again, revoke the lineage it came from, since the server "cannot
 * determine which party submitted the invalid refresh token" and a retry after
 * a lost response looks exactly like a theft.
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

    #[TestDox('the wider hammer ends every session the subject has, and nobody else\'s')]
    public function testEverySessionCanBeEnded(): void
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

    #[TestDox('an empty presentation is nothing to look up, not an exception to catch')]
    public function testEmptyPresentation(): void
    {
        // A form field nobody filled in reaches `consume()` as '', and an
        // application answering `invalid_grant` should not have to wrap the
        // call in a try/catch to say so. The hashing rule still refuses it —
        // that is where an empty string would otherwise become a digest.
        self::assertNull((new InMemoryRefreshTokenStore())->consume(''));

        $this->expectException(InvalidArgumentException::class);

        RefreshToken::hashOf('');
    }

    #[TestDox('a retry after a successful refresh looks exactly like a replay')]
    public function testARetryIsIndistinguishableFromTheft(): void
    {
        $now = FrozenClock::at('2026-09-02T12:00:00+00:00');
        $generator = self::generator($now);
        $store = new InMemoryRefreshTokenStore();

        $first = $generator->generate(new DateInterval('P30D'));
        $store->store($first, self::SUBJECT, 'grant-1');

        // The refresh that succeeded: spent, and the next one issued.
        $spent = $store->consume($first->value);
        self::assertInstanceOf(RefreshTokenRecord::class, $spent);
        self::assertTrue($spent->isUsable($now));
        $store->store($generator->generate(new DateInterval('P30D')), self::SUBJECT, $spent->grant);

        // The client never saw the response and sends the old value again.
        $retry = $store->consume($first->value);

        self::assertInstanceOf(RefreshTokenRecord::class, $retry);
        self::assertTrue($retry->alreadyUsed);

        // This is the point: the store cannot tell this from a stolen token,
        // and neither can the caller. RFC 9700 §4.14.2 says so in as many
        // words — the server "cannot determine which party submitted the
        // invalid refresh token" — and revokes anyway. An application that
        // wants retries to survive keeps a grace window of its own; the
        // contract does not have one, and this test is where that is written
        // down rather than discovered in production.
        self::assertSame('grant-1', $retry->grant);
    }

    #[TestDox('an expired token that gets retried is not evidence of theft')]
    public function testAnExpiredTokenIsNotAReplay(): void
    {
        $minted = FrozenClock::at('2026-09-02T12:00:00+00:00');
        $later = new \DateTimeImmutable('2026-09-02T12:10:00+00:00');
        $store = new InMemoryRefreshTokenStore();

        $token = self::generator($minted)->generate(new DateInterval('PT300S'));
        $store->store($token, self::SUBJECT, 'grant-1');

        // Presented after it expired: refused, and the row is spent doing it.
        $first = $store->consume($token->value);
        self::assertInstanceOf(RefreshTokenRecord::class, $first);
        self::assertFalse($first->alreadyUsed);
        self::assertTrue($first->isExpired($later));

        // The client retries the same dead token. It now reads as spent — so a
        // caller that treats `alreadyUsed` as theft without looking at the
        // expiry first would end every session over a token that had simply
        // run out.
        $retry = $store->consume($token->value);
        self::assertInstanceOf(RefreshTokenRecord::class, $retry);
        self::assertTrue($retry->alreadyUsed);
        self::assertTrue($retry->isExpired($later));
    }

    #[TestDox('revoking one lineage leaves the subject\'s other sessions alone')]
    public function testRevokingAGrant(): void
    {
        $now = FrozenClock::at('2026-09-02T12:00:00+00:00');
        $generator = self::generator($now);
        $store = new InMemoryRefreshTokenStore();

        $phone = $generator->generate(new DateInterval('P30D'));
        $store->store($phone, self::SUBJECT, 'grant-phone');
        $store->store($generator->generate(new DateInterval('P30D')), self::SUBJECT, 'grant-laptop');

        $store->consume($phone->value);
        $replay = $store->consume($phone->value);

        self::assertInstanceOf(RefreshTokenRecord::class, $replay);
        self::assertTrue($replay->alreadyUsed);
        self::assertSame('grant-phone', $replay->grant);

        // What RFC 9700 §4.14.2 actually asks for: the compromised lineage,
        // at the cost of that client authorizing again. The laptop keeps
        // working, which `revokeAllFor()` would not have allowed.
        self::assertNotNull($replay->grant);
        $store->revokeGrant($replay->grant);

        self::assertSame(1, $store->countFor(self::SUBJECT));
    }

    #[TestDox('storing the same token twice is refused rather than un-spending it')]
    public function testAStoreTakesAFreshToken(): void
    {
        $store = new InMemoryRefreshTokenStore();
        $token = self::generator(FrozenClock::at('2026-09-02T12:00:00+00:00'))->generate(new DateInterval('P30D'));

        $store->store($token, self::SUBJECT);
        $store->consume($token->value);

        $this->expectException(InvalidArgumentException::class);

        $store->store($token, self::SUBJECT);
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
