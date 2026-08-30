<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Jwe\Encrypter;
use Medzuch\Jwt\Key\OctKey;
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

    /** Exactly the 32 bytes A256KW is. */
    private const SEALING = '0123456789abcdef0123456789abcdef';

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

    #[TestDox('the key it verified against is in neither the data nor what is rendered (K9)')]
    public function testNoKeyMaterialReachesTheProfiler(): void
    {
        // The token has two tests of its own above. This is the other half of
        // K9 and the one nothing else covers: the key, and what is rendered
        // rather than the data behind it — a template is free to print
        // something the collector merely held, and `menu` reads the same
        // collector as `panel`.
        $client = self::createClient();
        $client->enableProfiler();

        $token = self::tokens()->token('alice', scopes: ['reports.read']);

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertResponseIsSuccessful();

        $panel = self::render($client);
        $menu = self::render($client, 'menu');

        // Rendered something first: a panel that collected nothing carries no
        // secret either, and would pass everything below.
        self::assertStringContainsString('alice', $panel);

        // Serialized, because that is what the profiler writes to disk and
        // what a later request reads back.
        $stored = serialize(self::collector($client));

        foreach (['the secret' => self::SECRET, 'the signature' => explode('.', $token)[2]] as $what => $material) {
            self::assertStringNotContainsString($material, $stored, sprintf('%s was collected', $what));
            self::assertStringNotContainsString($material, $panel, sprintf('%s is in the panel', $what));
            self::assertStringNotContainsString($material, $menu, sprintf('%s is in the menu', $what));
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

    /**
     * The panel used to say "this is not a JWT" about a token the consumer had
     * just accepted: `describe()` reads the bearer string before the handler
     * decrypts it, so a five-segment JWE took the same branch as garbage and
     * arrived with no algorithm, no key id and no claims (C12).
     *
     * The envelope is readable without a key, and that is what the panel shows
     * now. The claims are not, which is a different sentence.
     */
    #[TestDox('an accepted encrypted token is described by its envelope, not called garbage')]
    public function testEncryptedTokenIsCollectedAndRendered(): void
    {
        $client = self::createClient(['medzuch_jwt' => self::encryptedConfiguration()]);
        $client->enableProfiler();

        $client->request('GET', '/api/whoami', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::sealedTokens()->token('alice'),
        ]);

        self::assertResponseIsSuccessful();

        $tokens = self::collector($client)->tokens();

        self::assertSame('accepted', $tokens[0]['verdict']);
        self::assertSame('alice', $tokens[0]['identity']);
        self::assertSame('A256KW', $tokens[0]['alg']);
        self::assertSame('A256GCM', $tokens[0]['enc']);
        self::assertSame('enc-2026', $tokens[0]['kid']);
        // Real claims, behind a key this decorator does not hold.
        self::assertSame([], $tokens[0]['claims']);

        $panel = self::render($client);

        self::assertStringContainsString('A256GCM', $panel);
        self::assertStringContainsString('The claims are encrypted', $panel);
        self::assertStringNotContainsString('this is not a JWT', $panel);
    }

    #[TestDox('a refusal from inside the envelope keeps its own reason under the same sentence')]
    public function testRefusedEncryptedTokenKeepsItsReason(): void
    {
        $client = self::createClient(['medzuch_jwt' => self::encryptedConfiguration()]);
        $client->enableProfiler();

        $client->request('GET', '/api/whoami', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::sealedTokens()->expired('alice'),
        ]);

        self::assertResponseStatusCodeSame(401);

        $tokens = self::collector($client)->tokens();

        self::assertSame('refused', $tokens[0]['verdict']);
        self::assertSame('expired', $tokens[0]['reason']);
        self::assertSame('A256KW', $tokens[0]['alg']);

        self::assertStringNotContainsString('this is not a JWT', self::render($client));
    }

    #[TestDox('nothing of an encrypted token reaches the profile either')]
    public function testTheCiphertextIsNotCollected(): void
    {
        $client = self::createClient(['medzuch_jwt' => self::encryptedConfiguration()]);
        $client->enableProfiler();

        $token = self::sealedTokens()->token('alice');
        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertResponseIsSuccessful();

        $segments = explode('.', $token);
        self::assertCount(5, $segments);

        $stored = serialize(self::collector($client));
        $panel = self::render($client);

        // Every segment that is not the header: the wrapped key, the IV, the
        // ciphertext and the tag are together the whole of what makes this
        // token usable, and a profile is a file served back by a URL.
        foreach (array_slice($segments, 1) as $index => $segment) {
            self::assertStringNotContainsString($segment, $stored, sprintf('segment %d was collected', $index + 1));
            self::assertStringNotContainsString($segment, $panel, sprintf('segment %d is in the panel', $index + 1));
        }
    }

    /**
     * A JWE that names no key: the resolver falls back to the header's `alg`,
     * which is how a single-key consumer works, and the panel has to say so
     * rather than leave a row that reads as a value it could not decode.
     */
    #[TestDox('an encrypted token naming no key is shown as naming none')]
    public function testAnEncryptedTokenWithNoKeyId(): void
    {
        $client = self::createClient(['medzuch_jwt' => self::encryptedConfiguration()]);
        $client->enableProfiler();

        $token = (string) (new Encrypter())->encrypt(
            new A256Kw(),
            new A256Gcm(),
            ['cty' => 'JWT'],
            self::tokens()->token('alice'),
            OctKey::fromBinary(self::SEALING, 'A256KW', 'enc-2026'),
        );

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertResponseIsSuccessful();

        $tokens = self::collector($client)->tokens();

        self::assertSame('A256KW', $tokens[0]['alg']);
        self::assertSame('A256GCM', $tokens[0]['enc']);
        self::assertNull($tokens[0]['kid']);
        self::assertStringContainsString('(none named)', self::render($client));
    }

    private static function sealedTokens(): TestTokenFactory
    {
        return self::tokens()->encryptedWith(
            new A256Kw(),
            new A256Gcm(),
            OctKey::fromBinary(self::SEALING, 'A256KW', 'enc-2026'),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function encryptedConfiguration(): array
    {
        $configuration = self::configuration();
        $configuration['jwe_keys'] = ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256KW', 'kid' => 'enc-2026']];
        $configuration['consumers']['api']['jwe'] = [
            'keys' => ['sealed'],
            'allowed_key_management' => ['A256KW'],
            'allowed_content_encryption' => ['A256GCM'],
        ];

        return $configuration;
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

    private static function render(KernelBrowser $client, string $block = 'panel'): string
    {
        $twig = self::getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);

        return $twig->load('@MedzuchJwt/data_collector/jwt.html.twig')
            ->renderBlock($block, ['collector' => self::collector($client)]);
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
