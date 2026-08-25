<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\DataCollector\JwtDataCollector;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\TraceableAccessTokenHandler;
use Medzuch\JwtBundle\Test\TestTokenFactory;
use Medzuch\JwtBundle\Tests\Functional\App\ProfiledKernel;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Psr\Container\ContainerInterface;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\HttpKernel\Profiler\Profile;
use Twig\Environment;

/**
 * The panel, through a profiler that really collected it.
 *
 * A data collector is easy to test by calling its methods and easy to ship
 * broken anyway: what fails in life is the wiring that was supposed to feed it
 * and the template that reads it back. So this makes real requests and then
 * renders the real template against what the profiler stored.
 */
#[CoversClass(JwtDataCollector::class)]
#[CoversClass(TraceableAccessTokenHandler::class)]
final class ProfilerPanelTest extends WebTestCase
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

        return new ProfiledKernel(is_array($config) ? $config : []);
    }

    #[TestDox('an accepted token is collected with what it named and what it cost')]
    public function testAcceptedTokenIsCollected(): void
    {
        $client = self::createClient();
        $client->enableProfiler();

        $client->request('GET', '/api/whoami', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::tokens()->token('alice', scopes: ['reports.read']),
        ]);

        self::assertResponseIsSuccessful();

        $tokens = self::collector($client)->tokens();

        self::assertCount(1, $tokens);
        self::assertSame('api', $tokens[0]['consumer']);
        self::assertSame('accepted', $tokens[0]['verdict']);
        self::assertSame('alice', $tokens[0]['identity']);
        self::assertSame('HS256', $tokens[0]['alg']);
        $claims = $tokens[0]['claims'];
        self::assertIsArray($claims);
        self::assertSame('reports.read', $claims['scope'] ?? null);
        self::assertGreaterThan(0.0, $tokens[0]['duration']);
    }

    #[TestDox('a refused token is collected with the reason the response withholds')]
    public function testRefusedTokenIsCollected(): void
    {
        $client = self::createClient();
        $client->enableProfiler();

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . self::tokens()->expired('alice')]);

        self::assertResponseStatusCodeSame(401);

        $collector = self::collector($client);
        $tokens = $collector->tokens();

        self::assertCount(1, $tokens);
        self::assertSame('refused', $tokens[0]['verdict']);
        // The whole point of the panel: the wire says `invalid_token` and this
        // says which of the dozen things that covers.
        self::assertSame('expired', $tokens[0]['reason']);
        self::assertSame(1, $collector->refusals());

        // The claims of a token nobody accepted, which is what its reader needs.
        $claims = $tokens[0]['claims'];
        self::assertIsArray($claims);
        self::assertSame('alice', $claims['sub'] ?? null);
    }

    #[TestDox('the token itself is never collected, whatever else is')]
    public function testTheTokenIsNotCollected(): void
    {
        $client = self::createClient();
        $client->enableProfiler();

        $token = self::tokens()->token('alice');
        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        // Profiler data is written to disk and served back by a URL. The
        // signature is the part that makes the token usable, and nothing
        // collected may contain it.
        $signature = explode('.', $token)[2];

        self::assertStringNotContainsString($signature, serialize(self::collector($client)->tokens()));
    }

    #[TestDox('nor on a refusal, where the row carries a message somebody else wrote')]
    public function testTheTokenIsNotCollectedOnARefusalEither(): void
    {
        // `detail` is the only free text in a row and it exists only here: it
        // comes from a library exception, and an exception that ever quoted the
        // input it was given would put a credential in a file. This is the test
        // that would notice.
        foreach (['expired', 'garbage'] as $shape) {
            $token = 'expired' === $shape ? self::tokens()->expired('alice') : 'not.a.jwt';

            $client = self::createClient();
            $client->enableProfiler();
            $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

            $collected = serialize(self::collector($client)->tokens());

            self::assertStringNotContainsString($token, $collected, $shape);
            self::ensureKernelShutdown();
        }
    }

    #[TestDox('something that is not a JWT is collected as what it is, and rendered as what it is not')]
    public function testGarbageIsCollectedAndRendered(): void
    {
        $client = self::createClient();
        $client->enableProfiler();

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer not-a-jwt-at-all']);

        self::assertResponseStatusCodeSame(401);

        $tokens = self::collector($client)->tokens();

        self::assertSame('refused', $tokens[0]['verdict']);
        self::assertSame('malformed', $tokens[0]['reason']);
        // Nothing decoded, so nothing to name: the panel has a branch for each.
        self::assertNull($tokens[0]['alg']);
        self::assertNull($tokens[0]['kid']);
        self::assertSame([], $tokens[0]['claims']);

        $panel = self::render($client);

        self::assertStringContainsString('(unreadable)', $panel);
        self::assertStringContainsString('(none named)', $panel);
        self::assertStringContainsString('this is not a JWT', $panel);
    }

    #[TestDox('a refusal the application decided keeps the reason the event gives it')]
    public function testIdentityRefusalKeepsItsReason(): void
    {
        $client = self::createClient(['medzuch_jwt' => self::customModeConfiguration()]);
        $client->enableProfiler();

        // The factory refuses a token that names no tenant. That refusal is the
        // application's own exception, not this bundle's, so the reason has to
        // come from the one rule both the event and the panel read.
        $client->request('GET', '/api/whoami', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::tokens()->token('alice'),
        ]);

        self::assertResponseStatusCodeSame(401);

        $tokens = self::collector($client)->tokens();

        self::assertSame('refused', $tokens[0]['verdict']);
        self::assertSame('identity_refused', $tokens[0]['reason']);
    }

    #[TestDox('a request carrying no token collects nothing to show')]
    public function testNothingToShow(): void
    {
        $client = self::createClient();
        $client->enableProfiler();

        $client->request('GET', '/api/whoami');

        self::assertResponseStatusCodeSame(401);
        self::assertSame([], self::collector($client)->tokens());
    }

    #[TestDox('the panel renders what was collected')]
    public function testPanelRenders(): void
    {
        $client = self::createClient();
        $client->enableProfiler();

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . self::tokens()->expired('alice')]);

        $twig = self::getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);

        $context = ['collector' => self::collector($client)];
        $template = $twig->load('@MedzuchJwt/data_collector/jwt.html.twig');

        // Block by block rather than the whole page: the layout belongs to
        // WebProfilerBundle and wants a profile of its own, while these three
        // are the parts this bundle wrote and can get wrong.
        $panel = $template->renderBlock('panel', $context);

        self::assertStringContainsString('refused: expired', $panel);
        self::assertStringContainsString('Consumer', $panel);
        self::assertStringContainsString('HS256', $panel);
        // The claims table, and the note saying why the token is not in it.
        self::assertStringContainsString('alice', $panel);
        self::assertStringContainsString('not collected', $panel);

        self::assertStringContainsString('JWT', $template->renderBlock('menu', $context));

        // The toolbar block is compiled but not rendered: it includes
        // WebProfilerBundle's own item template, which reads a `name` and a
        // `token` the profiler puts in the context and builds a `_profiler`
        // URL from routes an application imports. Loading the template above
        // compiles every block in the file, so a syntax error in that one still
        // fails here — only its runtime is out of reach.
        self::assertTrue($template->hasBlock('toolbar', $context));
    }

    #[TestDox('the empty panel says so rather than showing an empty table')]
    public function testEmptyPanelRenders(): void
    {
        $client = self::createClient();
        $client->enableProfiler();

        $client->request('GET', '/api/whoami');

        $twig = self::getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);

        $panel = $twig->load('@MedzuchJwt/data_collector/jwt.html.twig')
            ->renderBlock('panel', ['collector' => self::collector($client)]);

        self::assertStringContainsString('No token was presented', $panel);
    }

    #[TestDox('without a profiler there is no collector, and nothing wrapping the handler')]
    public function testNothingIsWiredWithoutAProfiler(): void
    {
        // A kernel with the same firewall and no profiler, because that is the
        // shape production has. The other half of the pass matters there: a
        // decorator recording into nothing would sit on the hot path of every
        // authenticated request.
        $kernel = new SecuredKernel(self::configuration());
        $kernel->boot();

        $container = $kernel->getContainer()->get('test.service_container');
        self::assertInstanceOf(ContainerInterface::class, $container);

        self::assertFalse($container->has('medzuch_jwt.data_collector'));
        // The service the firewall calls, undecorated.
        self::assertInstanceOf(AccessTokenHandler::class, $container->get('security.access_token_handler.api'));

        $kernel->shutdown();
    }

    #[TestDox('the handler the firewall calls is wrapped, and the one it was made from is not')]
    public function testOnlyTheChildIsDecorated(): void
    {
        self::createClient();

        $container = self::getContainer();

        // The child, which is what SecurityBundle built from our definition.
        self::assertInstanceOf(TraceableAccessTokenHandler::class, $container->get('security.access_token_handler.api'));

        // And not the parent. Decorating that one is the fix somebody will
        // reach for when the panel is empty, and it would leave the child
        // inheriting from a decorator — broken rather than merely silent.
        self::assertInstanceOf(AccessTokenHandler::class, $container->get('medzuch_jwt.handler.api'));
    }

    private static function render(KernelBrowser $client): string
    {
        $twig = self::getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);

        return $twig->load('@MedzuchJwt/data_collector/jwt.html.twig')
            ->renderBlock('panel', ['collector' => self::collector($client)]);
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function customModeConfiguration(): array
    {
        $configuration = self::configuration();
        $configuration['consumers']['api']['user'] = ['mode' => 'custom', 'factory' => 'test.user_factory'];

        return $configuration;
    }

    #[TestDox('the key it verified against is in neither the data nor the panel (K9)')]
    public function testNoKeyMaterialReachesTheProfiler(): void
    {
        // The token has two tests of its own above. This is the other half of
        // K9 and the one nothing else covers: the key, and the rendered panel
        // rather than the data behind it — a template is free to print
        // something the collector merely held.
        $client = self::createClient();
        $client->enableProfiler();

        $token = self::tokens()->token('alice', scopes: ['reports.read']);

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertResponseIsSuccessful();

        $collector = self::collector($client);

        $twig = self::getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);

        $panel = $twig->load('@MedzuchJwt/data_collector/jwt.html.twig')
            ->renderBlock('panel', ['collector' => $collector]);

        // Rendered something first: a panel that collected nothing carries no
        // secret either, and would pass everything below.
        self::assertStringContainsString('alice', $panel);

        // Serialized, because that is what the profiler writes to disk and
        // what a later request reads back.
        self::assertStringNotContainsString(self::SECRET, serialize($collector));
        self::assertStringNotContainsString(self::SECRET, $panel);
        self::assertStringNotContainsString(explode('.', $token)[2], $panel);
    }

    private static function collector(KernelBrowser $client): JwtDataCollector
    {
        $profile = $client->getProfile();
        self::assertInstanceOf(Profile::class, $profile);

        $collector = $profile->getCollector('medzuch_jwt');
        self::assertInstanceOf(JwtDataCollector::class, $collector);

        return $collector;
    }

    private static function tokens(): TestTokenFactory
    {
        return TestTokenFactory::hmac(self::ISSUER, self::AUDIENCE, self::SECRET);
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function configuration(): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => [
                'issuer' => self::ISSUER,
                'audience' => self::AUDIENCE,
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
                'user' => ['mode' => 'claims'],
            ]],
        ];
    }
}
