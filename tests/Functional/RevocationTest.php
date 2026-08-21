<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateTimeImmutable;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Revocation\CacheTokenDenylist;
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\ArrayCache;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * Tokens refused before their own `exp` says so.
 *
 * A JWT is valid because it verifies, which is the trade that makes it
 * stateless; revocation buys back the willingness to refuse one, at the price
 * of a lookup per request. Both halves are asserted here — that a revoked token
 * stops working, and that an unconfigured consumer asks nothing at all.
 */
#[CoversClass(CacheTokenDenylist::class)]
final class RevocationTest extends KernelTestCase
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

    #[TestDox('a token verifies until it is revoked, and is refused after')]
    public function testRevokedTokenIsRefused(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $token = self::issuer()->issue('user-42');

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());

        self::denylist()->revoke($token->jti, new DateTimeImmutable('+1 hour'));

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessageMatches('/has been revoked/');

        self::handler()->getUserBadgeFrom($token->value);
    }

    #[TestDox('revoking one token leaves the others alone')]
    public function testRevocationIsPerToken(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $revoked = self::issuer()->issue('user-42');
        $other = self::issuer()->issue('user-42');

        self::denylist()->revoke($revoked->jti, new DateTimeImmutable('+1 hour'));

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($other->value)->getUserIdentifier());
        self::assertNotSame($revoked->jti, $other->jti, 'each token should be nameable on its own');
    }

    #[TestDox('the entry is kept only as long as the token it refuses')]
    public function testEntryOutlivesNothing(): void
    {
        $config = self::configuration();
        $config['clock'] = 'test.frozen_clock';

        self::bootKernel(['medzuch_jwt' => $config]);

        $denylist = self::denylist();
        $denylist->revoke('some-jti', self::clock()->now()->modify('+300 seconds'));

        // An entry that outlived the token would be a row nobody can ever read
        // again: after `exp` the token is refused on its own terms (DEC-3).
        self::assertSame([300], array_values(array_filter(self::cache()->ttls, static fn(mixed $ttl): bool => null !== $ttl)));
    }

    #[TestDox('revoking a token that has already expired writes nothing')]
    public function testExpiredTokenIsNotWorthAnEntry(): void
    {
        $config = self::configuration();
        $config['clock'] = 'test.frozen_clock';

        self::bootKernel(['medzuch_jwt' => $config]);

        self::denylist()->revoke('some-jti', self::clock()->now()->modify('-1 second'));

        self::assertSame([], self::cache()->ttls);
    }

    #[TestDox('an unconfigured consumer asks nothing, and holds no denylist to ask')]
    public function testWithoutADenylistNothingIsAsked(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(denylist: [])]);

        $token = self::issuer()->issue('user-42');
        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());
        self::assertSame([], self::cache()->ttls, 'nothing should have touched the cache');
    }

    #[TestDox('an unconfigured consumer registers no denylist service either')]
    public function testNoServiceWithoutConfiguration(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(denylist: [])]);

        self::assertFalse(self::getContainer()->has('medzuch_jwt.denylist.api'));
    }

    #[TestDox('a denylist of your own answers under the same name')]
    public function testCustomDenylistService(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(denylist: ['service' => 'test.denylist'])]);

        $token = self::issuer()->issue('user-42');
        self::denylist()->revoke($token->jti, new DateTimeImmutable('+1 hour'));

        $this->expectException(BadCredentialsException::class);
        $this->expectExceptionMessageMatches('/has been revoked/');

        self::handler()->getUserBadgeFrom($token->value);
    }

    #[TestDox('a consumer naming two kinds of denylist fails at container build')]
    public function testTwoDenylists(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/Give one: a service of your own/');

        self::bootKernel(['medzuch_jwt' => self::configuration(denylist: ['cache' => 'test.cache', 'service' => 'test.cache'])]);
    }

    #[TestDox('a prefix that would overflow a PSR-16 key fails at container build')]
    public function testOverlongPrefix(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/past the 64 PSR-16 guarantees/');

        self::bootKernel(['medzuch_jwt' => self::configuration(denylist: ['cache' => 'test.cache', 'prefix' => str_repeat('x', 33)])]);
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

    /** The bundle's own service, not one built here: what revokes has to be reachable. */
    private static function denylist(): TokenDenylistInterface
    {
        $denylist = self::getContainer()->get('medzuch_jwt.denylist.api');
        self::assertInstanceOf(TokenDenylistInterface::class, $denylist);

        return $denylist;
    }

    private static function cache(): ArrayCache
    {
        $cache = self::getContainer()->get('test.cache');
        self::assertInstanceOf(ArrayCache::class, $cache);

        return $cache;
    }

    private static function clock(): FrozenClock
    {
        $clock = self::getContainer()->get('test.frozen_clock');
        self::assertInstanceOf(FrozenClock::class, $clock);

        return $clock;
    }

    /**
     * @param array<string, mixed> $denylist an empty array configures none
     *
     * @return array<string, mixed>
     */
    private static function configuration(array $denylist = ['cache' => 'test.cache']): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => [
                'issuer' => 'https://issuer.test',
                'key' => 'default',
                'client_id' => 'test-client',
                'audience' => 'https://api.test',
            ]],
            'consumers' => ['api' => [
                'issuer' => 'https://issuer.test',
                'audience' => 'https://api.test',
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
                'denylist' => $denylist,
            ]],
        ];
    }
}
