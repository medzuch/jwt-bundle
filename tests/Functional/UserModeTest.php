<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\User\JwtUser;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Who a verified token turns out to be.
 *
 * `provider` hands an identifier to the application's store; `claims` builds
 * the user out of the token, for a resource server with nothing to look up;
 * `custom` gives the claims to a service of the application's own.
 */
#[CoversClass(AccessTokenHandler::class)]
final class UserModeTest extends KernelTestCase
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

    #[TestDox('the default mode hands the identifier on, and builds no user itself')]
    public function testProviderModeCarriesOnlyTheIdentifier(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $badge = self::badgeFor(self::token());

        self::assertSame('user-42', $badge->getUserIdentifier());
        self::assertNull($badge->getUserLoader(), 'provider mode should leave the loading to the firewall');
    }

    #[TestDox('claims mode builds the user from the token, with the claims kept')]
    public function testClaimsModeBuildsTheUser(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['mode' => 'claims'])]);

        $user = self::userFor(self::token());

        self::assertSame('user-42', $user->getUserIdentifier());
        self::assertSame('tenant-7', $user->claims()->getString('tenant'));
    }

    /**
     * @param array<string, mixed> $roles
     * @param list<string>         $expected
     */
    #[DataProvider('roleMappings')]
    #[TestDox('roles from claims: $_dataName')]
    public function testRoleMapping(array $roles, array $expected): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['mode' => 'claims', 'roles' => $roles])]);

        self::assertSame($expected, self::userFor(self::token())->getRoles());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, list<string>}>
     */
    public static function roleMappings(): iterable
    {
        // `scope` is space-delimited by RFC 6749 §3.3, which is why that is the
        // separator's default.
        yield 'a delimited scope claim' => [['claim' => 'scope'], ['ROLE_read', 'ROLE_write']];
        yield 'a list claim' => [['claim' => 'groups'], ['ROLE_staff', 'ROLE_billing']];
        yield 'a prefix of your own' => [['claim' => 'scope', 'prefix' => 'SCOPE_'], ['SCOPE_read', 'SCOPE_write']];
        yield 'no prefix at all' => [['claim' => 'groups', 'prefix' => ''], ['staff', 'billing']];
        yield 'a baseline everyone gets' => [['claim' => 'scope', 'defaults' => ['ROLE_USER']], ['ROLE_USER', 'ROLE_read', 'ROLE_write']];
        yield 'defaults alone, with no claim' => [['defaults' => ['ROLE_USER']], ['ROLE_USER']];
        // A claim the issuer did not send is not an error: the token grants
        // nothing beyond the baseline.
        yield 'a claim the token does not carry' => [['claim' => 'entitlements'], []];
        // Only strings become roles; a nested object would otherwise arrive as
        // a role named after its type.
        yield 'a claim holding something else' => [['claim' => 'nested'], []];
    }

    #[TestDox('custom mode names the user itself: the badge agrees with the user it loads')]
    public function testCustomModeNamesTheUser(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['mode' => 'custom', 'factory' => 'test.user_factory'])]);

        $badge = self::badgeFor(self::token());

        // The factory derives an identity the token carries in no single
        // claim; a badge still named after `sub` would put two identities in
        // the logs for one request.
        self::assertSame('user-42@tenant-7', $badge->getUserIdentifier());
    }

    #[TestDox('custom mode asks the application, and its refusal is an authentication failure')]
    public function testCustomMode(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['mode' => 'custom', 'factory' => 'test.user_factory'])]);

        $user = self::userFor(self::token());

        self::assertSame('user-42@tenant-7', $user->getUserIdentifier());
        self::assertSame(['ROLE_TENANT'], $user->getRoles());
    }

    #[TestDox('custom mode without a factory fails at container build')]
    public function testCustomModeWithoutFactory(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/names no "factory"/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['mode' => 'custom'])]);
    }

    #[TestDox('a factory named by a mode that never calls one fails at container build')]
    public function testFactoryInTheWrongMode(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/never calls one/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['factory' => 'test.user_factory'])]);
    }

    #[TestDox('role mapping in a mode that gets roles elsewhere fails at container build')]
    public function testRolesInTheWrongMode(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/roles come from the user provider/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['roles' => ['claim' => 'scope']])]);
    }

    #[TestDox('an empty roles separator fails at container build, not when a token arrives')]
    public function testEmptySeparator(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/splitting on nothing/');

        self::bootKernel(['medzuch_jwt' => self::configuration(['mode' => 'claims', 'roles' => ['claim' => 'scope', 'separator' => '']])]);
    }

    #[TestDox('a string claim taken whole becomes one role')]
    public function testSeparatorlessClaim(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['mode' => 'claims', 'roles' => ['claim' => 'tenant', 'separator' => null, 'prefix' => 'TENANT_']])]);

        self::assertSame(['TENANT_tenant-7'], self::userFor(self::token())->getRoles());
    }

    private static function token(): string
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer->issue('user-42', claims: [
            'scope' => 'read write',
            'groups' => ['staff', 'billing'],
            'tenant' => 'tenant-7',
            'nested' => ['deep' => 'value'],
        ])->value;
    }

    private static function badgeFor(string $token): \Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler->getUserBadgeFrom($token);
    }

    private static function userFor(string $token): JwtUser
    {
        $badge = self::badgeFor($token);
        $loader = $badge->getUserLoader();

        self::assertIsCallable($loader, 'a mode that builds its own user should carry a loader');

        $user = $loader($badge->getUserIdentifier());
        self::assertInstanceOf(JwtUser::class, $user);

        return $user;
    }

    /**
     * @param array<string, mixed> $user
     *
     * @return array<string, mixed>
     */
    private static function configuration(array $user = []): array
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
                'user' => $user,
            ]],
        ];
    }
}
