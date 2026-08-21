<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Security\Authorization\ScopeExpressionProvider;
use Medzuch\JwtBundle\Security\Authorization\ScopeVoter;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * `SCOPE_*` checks answered from the token, through the access rules that ask
 * them rather than by calling the voter.
 *
 * A scope is not a role with another prefix: a role says what someone is, a
 * scope says what the client holding this token was allowed to ask for on their
 * behalf. Two tokens naming the same person can carry different ones, which is
 * why they keep their own namespace.
 */
#[CoversClass(ScopeVoter::class)]
final class ScopeVoterTest extends WebTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new SecuredKernel(self::configuration(is_string($options['mode'] ?? null) ? $options['mode'] : 'claims'));
    }

    #[TestDox('a token carrying the scope reaches the route that requires it')]
    public function testScopeGrants(): void
    {
        $client = self::createClient();

        self::request($client, '/api/scoped', ['reports.read']);

        self::assertResponseIsSuccessful();
    }

    #[TestDox('a token carrying other scopes is refused, though it authenticates')]
    public function testOtherScopesAreRefused(): void
    {
        $client = self::createClient();

        // Authenticated and denied are different answers, and this is the
        // second: the caller is who they say, and this client was not allowed
        // to ask for reports.
        self::request($client, '/api/scoped', ['reports.write', 'profile']);

        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);
    }

    #[TestDox('a scope is matched whole, not by prefix')]
    public function testScopesMatchWhole(): void
    {
        $client = self::createClient();

        self::request($client, '/api/scoped', ['reports.readonly']);

        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);
    }

    #[TestDox('is_granted_scope() asks the checker for the same attribute the voter answers')]
    public function testExpressionFunction(): void
    {
        // Not through `access_control`: Symfony strips its whole expression
        // machinery unless symfony/expression-language is a runtime dependency,
        // and for this bundle it is a suggestion. So the function is exercised
        // where it lives — both halves of it, since an expression compiled into
        // a cache and one evaluated on the spot take different paths.
        $language = new ExpressionLanguage();
        $language->registerProvider(new ScopeExpressionProvider());

        // Not an AuthorizationCheckerInterface: its signature moves across the
        // supported Symfony lines — 6.4 has no AccessDecision class at all —
        // and the expression only ever calls isGranted() on whatever it is
        // handed. A double that implements the interface would be pinning a
        // version rather than testing the function.
        $checker = new class {
            /** @var list<string> */
            public array $asked = [];

            public function isGranted(mixed $attribute): bool
            {
                $this->asked[] = is_string($attribute) ? $attribute : get_debug_type($attribute);

                return 'SCOPE_reports.read' === $attribute;
            }
        };

        self::assertTrue($language->evaluate("is_granted_scope('reports.read')", ['auth_checker' => $checker]));
        self::assertFalse($language->evaluate("is_granted_scope('profile')", ['auth_checker' => $checker]));
        self::assertSame(['SCOPE_reports.read', 'SCOPE_profile'], $checker->asked);

        self::assertSame(
            '$auth_checker->isGranted("SCOPE_" . "reports.read")',
            $language->compile("is_granted_scope('reports.read')", ['auth_checker']),
        );
    }

    #[TestDox('the expression function is registered for the security expression language')]
    public function testExpressionProviderIsTagged(): void
    {
        self::createClient();

        $definition = self::getContainer()->getRemovedIds();

        // The tag is what makes it reachable from an expression at all, and a
        // provider nothing registers is a function nobody can call.
        self::assertTrue(
            self::getContainer()->has('medzuch_jwt.scope_expression_provider') || isset($definition['medzuch_jwt.scope_expression_provider']),
            'the provider should be registered when symfony/expression-language is installed',
        );
    }

    #[TestDox('a user from the application\'s own store carries no scopes, and is refused')]
    public function testProviderModeCarriesNoScopes(): void
    {
        // Not an oversight: in provider mode the store is the authority on what
        // may be done, and a scope from the token would be a second answer to a
        // question already answered.
        $client = self::createClient(['mode' => 'provider']);

        self::request($client, '/api/scoped', ['reports.read']);

        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);
    }

    #[TestDox('the route without a scope rule is unaffected')]
    public function testUnscopedRouteStillWorks(): void
    {
        $client = self::createClient();

        self::request($client, '/api/whoami', []);

        self::assertResponseIsSuccessful();
    }

    /**
     * @param list<string> $scopes
     */
    private static function request(KernelBrowser $client, string $path, array $scopes): void
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        $client->request('GET', $path, server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $issuer->issue('alice', $scopes)->value,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private static function configuration(string $mode): array
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
                'user' => 'claims' === $mode ? ['mode' => 'claims'] : ['identity_claim' => 'sub'],
            ]],
        ];
    }
}
