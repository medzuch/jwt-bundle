<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\NestedJwtBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\Jwt\Profile\IdTokenProfile;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Oidc\IdTokenVerifier;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Tests\Functional\App\CollectingLogger;
use Medzuch\JwtBundle\Tests\Functional\App\StubHttpClient;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * What level each kind of diagnostic is emitted at.
 *
 * The library decides the level and the application's logger decides whether
 * to record it, so the only thing worth asserting here is that a configured
 * level reaches the library — which means reading the level off what was
 * actually logged rather than off the container.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class LogLevelsTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';
    private const JWKS_URI = 'https://idp.test/.well-known/jwks.json';

    /** Exactly the 32 bytes A256KW is. */
    private const SEALING = '0123456789abcdef0123456789abcdef';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('unconfigured, the library keeps its own defaults')]
    public function testTheLibraryDefaults(): void
    {
        self::bootKernel();

        self::handler()->getUserBadgeFrom(self::token());
        self::refuse(self::token(expiresAt: new DateTimeImmutable('-1 hour')));

        // `debug` for an accepted token and `notice` for a claim refused: the
        // library's, not this bundle's, and asserted so that a change to them
        // shows up here rather than in somebody's log volume.
        self::assertSame('debug', self::levelOf('accepted'));
        self::assertSame('notice', self::levelOf('rejected'));
    }

    #[TestDox('a configured level is what the library emits at')]
    public function testAConfiguredLevelReachesTheLibrary(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration([
            'accepted' => 'info',
            'claim_rejected' => 'warning',
        ])]);

        self::handler()->getUserBadgeFrom(self::token());
        self::refuse(self::token(expiresAt: new DateTimeImmutable('-1 hour')));

        self::assertSame('info', self::levelOf('accepted'));
        self::assertSame('warning', self::levelOf('rejected'));
    }

    #[TestDox('a category left alone keeps its default beside one that was set')]
    public function testOneCategoryAtATime(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(['claim_rejected' => 'error'])]);

        self::handler()->getUserBadgeFrom(self::token());
        self::refuse(self::token(expiresAt: new DateTimeImmutable('-1 hour')));

        // Named arguments are why: setting one category must not restate the
        // other six at whatever this bundle believed their defaults were.
        self::assertSame('error', self::levelOf('rejected'));
        self::assertSame('debug', self::levelOf('accepted'));
    }

    #[TestDox('a consumer with its own token_type gets the configured levels too')]
    public function testACustomTokenTypeReachesTheLibrary(): void
    {
        // A different code path entirely: `token_type` builds a bare validator
        // through `CustomValidatorFactory` instead of a profile consumer, and
        // the levels have to be handed to `ValidatorBuilder::withLogger()`
        // rather than to `AccessTokenProfile::consumer()`.
        self::bootKernel(['medzuch_jwt' => self::customTypeConfiguration(['claim_rejected' => 'error'])]);

        self::handler()->getUserBadgeFrom(self::customToken());
        self::refuse(self::customToken(expiresAt: new DateTimeImmutable('-1 hour')));

        self::assertSame('error', self::levelOf('rejected'));
        self::assertSame('debug', self::levelOf('accepted'));
    }

    #[TestDox('an ID-token registration gets the configured levels too')]
    public function testIdTokensReachTheLibrary(): void
    {
        self::bootKernel(['medzuch_jwt' => self::idTokenConfiguration(['accepted' => 'info', 'claim_rejected' => 'critical'])]);

        $verifier = self::getContainer()->get('medzuch_jwt.id_token.partner');
        self::assertInstanceOf(IdTokenVerifier::class, $verifier);

        $verifier->verify(self::idToken());
        self::assertSame('info', self::levelOf('accepted'));

        try {
            $verifier->verify(self::idToken(audience: 'someone-else'));
            self::fail('the token should have been refused');
        } catch (JwtException) {
        }

        self::assertSame('critical', self::levelOf('rejected'));
    }

    #[TestDox('a remote JWK Set gets the two key-resolution levels')]
    public function testRemoteJwksReachesTheLibrary(): void
    {
        // The only service that emits `key_resolution` and
        // `key_resolution_failed` at all, and the failure is the one the
        // README calls worth watching.
        self::bootKernel(['medzuch_jwt' => self::remoteJwksConfiguration([
            'key_resolution' => 'info',
            'key_resolution_failed' => 'critical',
        ])]);

        // The outage first, because a fetch that succeeded would be cached and
        // the second verification would never reach the network.
        self::client()->goesOffline();

        try {
            self::remoteHandler()->getUserBadgeFrom(self::remoteToken());
            self::fail('an unreachable identity provider should not verify a token');
        } catch (AuthenticationException) {
        }

        self::assertSame('critical', self::levelOf('jwks resolution failed'));

        self::logger()->records = [];
        self::publish();

        self::assertSame('user-42', self::remoteHandler()->getUserBadgeFrom(self::remoteToken())->getUserIdentifier());
        self::assertSame('info', self::levelOf('jwks resolved'));
    }

    #[TestDox('a consumer that decrypts gets the two JWE levels')]
    public function testDecryptionReachesTheLibrary(): void
    {
        // The only service that emits `decrypted` and `decryption_failed`, and
        // the pair the option list waited on: before C12 nothing here built a
        // decrypter, so a level for either was one nothing would emit at.
        self::bootKernel(['medzuch_jwt' => self::jweConfiguration([
            'decrypted' => 'info',
            'decryption_failed' => 'critical',
        ])]);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom(self::sealed(self::token()))->getUserIdentifier());
        self::assertSame('info', self::levelOf('decrypted'));

        self::logger()->records = [];
        self::refuse(self::sealed(self::token(), OctKey::fromBinary(strrev(self::SEALING), 'A256KW', 'enc-2026')));

        self::assertSame('critical', self::levelOf('decryption failed'));
    }

    private static function sealed(string $signed, ?OctKey $key = null): string
    {
        $key ??= OctKey::fromBinary(self::SEALING, 'A256KW', 'enc-2026');

        return (string) NestedJwtBuilder::wrap(new CompactJws($signed), new A256Kw(), new A256Gcm(), $key, ['kid' => 'enc-2026']);
    }

    /**
     * @param array<string, string> $levels
     *
     * @return array<string, mixed>
     */
    private static function jweConfiguration(array $levels): array
    {
        $configuration = self::configuration($levels);
        $consumers = $configuration['consumers'];
        \assert(is_array($consumers) && is_array($consumers['api']));
        $consumers['api']['jwe'] = [
            'keys' => ['sealed'],
            'allowed_key_management' => ['A256KW'],
            'allowed_content_encryption' => ['A256GCM'],
        ];
        $configuration['consumers'] = $consumers;
        $configuration['jwe_keys'] = ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256KW', 'kid' => 'enc-2026']];

        return $configuration;
    }

    #[TestDox('a level that is not a PSR-3 one fails at container build')]
    public function testAnUnknownLevelIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('must be one of the eight PSR-3 levels');

        self::bootKernel(['medzuch_jwt' => self::configuration(['accepted' => 'chatty'])]);
    }

    #[TestDox('levels without a logger fail at container build')]
    public function testLevelsNeedALogger(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('nothing would emit at those levels');

        $configuration = self::configuration(['accepted' => 'info']);
        unset($configuration['logger']);

        self::bootKernel(['medzuch_jwt' => $configuration]);
    }

    /**
     * The level of the first record whose message names an outcome.
     */
    private static function levelOf(string $outcome): string
    {
        $logger = self::logger();

        foreach ($logger->records as $record) {
            if (str_contains(strtolower($record['message']), $outcome)) {
                return $record['level'];
            }
        }

        self::fail(sprintf('nothing was logged about a token being %s; got %s', $outcome, json_encode($logger->records)));
    }

    private static function logger(): CollectingLogger
    {
        $logger = self::getContainer()->get('test.logger');
        self::assertInstanceOf(CollectingLogger::class, $logger);

        return $logger;
    }

    private static function refuse(string $token): void
    {
        try {
            self::handler()->getUserBadgeFrom($token);
        } catch (AuthenticationException) {
            return;
        }

        self::fail('the token should have been refused');
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * @param array<string, string> $levels
     *
     * @return array<string, mixed>
     */
    private static function configuration(array $levels = []): array
    {
        $configuration = [
            'logger' => 'test.logger',
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => [
                'issuer' => self::ISSUER,
                'audience' => self::AUDIENCE,
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
            ]],
        ];

        if ([] !== $levels) {
            $configuration['log_levels'] = $levels;
        }

        return $configuration;
    }

    private static function token(?DateTimeImmutable $expiresAt = null): string
    {
        $builder = AccessTokenProfile::issuer(self::ISSUER, new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'))
            ->issue()
            ->subject('user-42')
            ->audience(self::AUDIENCE)
            ->clientId('test-client');

        return (string) (null === $expiresAt
            ? $builder->expiresIn(new DateInterval('PT5M'))
            : $builder->expiresAt($expiresAt))->build();
    }

    /**
     * @param array<string, string> $levels
     *
     * @return array<string, mixed>
     */
    private static function customTypeConfiguration(array $levels): array
    {
        $configuration = self::configuration($levels);
        $consumers = $configuration['consumers'];
        \assert(is_array($consumers) && is_array($consumers['api']));
        $consumers['api']['token_type'] = 'vnd.acme.session+jwt';
        $configuration['consumers'] = $consumers;

        return $configuration;
    }

    private static function customToken(?DateTimeImmutable $expiresAt = null): string
    {
        return (string) JwtBuilder::create()
            ->type('vnd.acme.session+jwt')
            ->issuer(self::ISSUER)
            ->subject('user-42')
            ->audience(self::AUDIENCE)
            ->expiresAt($expiresAt ?? new DateTimeImmutable('+5 minutes'))
            ->signWith(new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'))
            ->build();
    }

    /**
     * @param array<string, string> $levels
     *
     * @return array<string, mixed>
     */
    private static function idTokenConfiguration(array $levels): array
    {
        return [
            'logger' => 'test.logger',
            'log_levels' => $levels,
            'keys' => ['idp' => ['pem_public' => self::keypair('idp')['public'], 'algorithm' => 'RS256', 'kid' => 'idp-2026']],
            'id_tokens' => ['partner' => [
                'issuer' => self::ISSUER,
                'client_id' => 'client-42',
                'keys' => ['idp'],
                'allowed_algorithms' => ['RS256'],
            ]],
        ];
    }

    private static function idToken(string $audience = 'client-42'): string
    {
        return (string) IdTokenProfile::issuer(
            self::ISSUER,
            new Rs256(),
            RsaPrivateKey::fromPem(self::keypair('idp')['private'], 'RS256', 'idp-2026'),
        )
            ->issue()
            ->subject('user-42')
            ->audience($audience)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();
    }

    /**
     * @param array<string, string> $levels
     *
     * @return array<string, mixed>
     */
    private static function remoteJwksConfiguration(array $levels): array
    {
        return [
            'logger' => 'test.logger',
            'log_levels' => $levels,
            'keys' => ['signing' => ['pem_private' => self::keypair('idp')['private'], 'algorithm' => 'RS256', 'kid' => 'idp-2026']],
            'issuers' => ['idp' => [
                'issuer' => self::ISSUER,
                'key' => 'signing',
                'client_id' => 'test-client',
                'audience' => self::AUDIENCE,
            ]],
            'remote_jwks' => ['partner_idp' => [
                'uri' => self::JWKS_URI,
                'http_client' => 'test.http_client',
                'cache' => 'test.cache',
            ]],
            'consumers' => ['partner' => [
                'issuer' => self::ISSUER,
                'audience' => self::AUDIENCE,
                'keys' => [],
                'remote_jwks' => 'partner_idp',
                'allowed_algorithms' => ['RS256'],
            ]],
        ];
    }

    private static function publish(): void
    {
        $jwk = RsaPrivateKey::fromPem(self::keypair('idp')['private'], 'RS256', 'idp-2026')->toPublicKey()->toJwk();

        self::client()->publishes(json_encode(['keys' => [$jwk]], \JSON_THROW_ON_ERROR));
    }

    private static function remoteToken(): string
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.idp');
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer->issue('user-42')->value;
    }

    private static function remoteHandler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.partner');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    private static function client(): StubHttpClient
    {
        $client = self::getContainer()->get('test.http_client');
        self::assertInstanceOf(StubHttpClient::class, $client);

        return $client;
    }
}
