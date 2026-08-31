<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\JwtBundle\Oidc\IdTokenIssuer;
use Medzuch\JwtBundle\Oidc\IdTokenVerifier;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * This application as an OpenID Connect provider (I6), asserted against its own
 * relying-party half: what `id_token_issuers` mints, `id_tokens` verifies.
 *
 * The pair is the point. A test that minted and then read the claims back with
 * a parser would prove the builder was called; verifying through
 * {@see IdTokenVerifier} proves the token is one a relying party accepts —
 * issuer, audience, signature, expiry and the required claims of the OIDC
 * profile, checked by the code that would check somebody else's.
 */
#[CoversClass(IdTokenIssuer::class)]
final class IdTokenIssuanceTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const ISSUER = 'https://op.test';

    private const CLIENT = 'client-42';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('an ID token this application mints is one its own relying-party half accepts')]
    public function testTheTwoHalvesMeet(): void
    {
        self::bootKernel();

        $idToken = (string) self::issuer()->issue()->subject('user-42')->build();

        $claims = self::verifier()->verify($idToken);

        self::assertSame('user-42', $claims->getString('sub'));
        self::assertSame(self::ISSUER, $claims->getString('iss'));
        self::assertSame(self::CLIENT, $claims->get('aud'));
    }

    /**
     * What the flow produced is the caller's to add, which is the whole reason
     * a builder comes back rather than a token: `nonce` binds this token to the
     * authentication request that asked for it (OIDC Core §3.1.3.7), and the
     * verifier is given the same value to compare against.
     */
    #[TestDox('the nonce the caller writes is the one a relying party checks')]
    public function testNonceRoundTrips(): void
    {
        self::bootKernel();

        $idToken = (string) self::issuer()->issue()
            ->subject('user-42')
            ->nonce('n-0S6_WzA2Mj')
            ->authTime(new DateTimeImmutable('-2 minutes'))
            ->acr('urn:mace:incommon:iap:silver')
            ->amr(['pwd', 'otp'])
            ->build();

        $claims = self::verifier()->verify($idToken, 'n-0S6_WzA2Mj');

        self::assertSame('n-0S6_WzA2Mj', $claims->getString('nonce'));
        self::assertSame('urn:mace:incommon:iap:silver', $claims->getString('acr'));
        self::assertSame(['pwd', 'otp'], $claims->get('amr'));
    }

    #[TestDox('the lifetime is the configured one, and the caller can still shorten it')]
    public function testLifetime(): void
    {
        self::bootKernel();

        self::assertSame(300, self::lifetimeOf((string) self::issuer()->issue()->subject('user-42')->build()));

        $shorter = (string) self::issuer()->issue()
            ->subject('user-42')
            ->expiresIn(new DateInterval('PT60S'))
            ->build();

        self::assertSame(60, self::lifetimeOf($shorter));
    }

    /**
     * A provider mints for whichever relying party asked, so the audience
     * belongs to the request. The configured one is a default for the
     * application that serves a single client.
     */
    #[TestDox('the client id given per token wins over the configured default')]
    public function testClientIdPerToken(): void
    {
        self::bootKernel();

        $idToken = (string) self::issuer()->issue('client-99')->subject('user-42')->build();

        self::assertSame('client-99', JwtParser::parse($idToken)->unverifiedClaims->get('aud'));

        // And the registration for client-42 refuses it, which is what an
        // audience is for.
        $this->expectException(\Medzuch\Jwt\Exception\JwtException::class);
        self::verifier()->verify($idToken);
    }

    #[TestDox('a provider serving several clients has to be told which one')]
    public function testWithoutAnyClientId(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(clientId: null)]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/has to name the relying party it is for/');

        self::issuer()->issue();
    }

    /**
     * An ID token says who signed in, to the client that asked. It is not a
     * bearer credential, and a consumer of this bundle will not take one: the
     * RFC 9068 profile it verifies expects `at+jwt`, and an ID token is not
     * that. The refusal is the design working rather than a gap.
     */
    #[TestDox('an ID token is not an access token, and a consumer says so')]
    public function testAnIdTokenIsNotACredential(): void
    {
        self::bootKernel();

        $idToken = (string) self::issuer()->issue()->subject('user-42')->build();

        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        try {
            $handler->getUserBadgeFrom($idToken);
            self::fail('an ID token should not authenticate a request');
        } catch (RejectedTokenException $failure) {
            // `malformed`, not a claim refusal: the RFC 9068 profile refuses
            // it on the `typ` in its header, before a claim is read. Refused
            // for what it is rather than for what it says.
            self::assertSame(RejectionReason::Malformed, $failure->reason);
            self::assertStringContainsString('at+jwt', strtolower((string) $failure->getPrevious()?->getMessage()));
        }
    }

    #[TestDox('a provider signing with a key that has no private half fails at container build')]
    public function testPublicOnlyKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/ID token issuer "op" signs with key "verify_only", which has only a public half/');

        self::bootKernel(['medzuch_jwt' => self::configuration(key: 'verify_only')]);
    }

    private static function lifetimeOf(string $idToken): int
    {
        $claims = JwtParser::parse($idToken)->unverifiedClaims;

        $expiry = $claims->getInt('exp');
        $issued = $claims->getInt('iat');

        self::assertIsInt($expiry);
        self::assertIsInt($issued);

        return $expiry - $issued;
    }

    private static function issuer(): IdTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.id_token_issuer.op');
        self::assertInstanceOf(IdTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function verifier(): IdTokenVerifier
    {
        $verifier = self::getContainer()->get('medzuch_jwt.id_token.self');
        self::assertInstanceOf(IdTokenVerifier::class, $verifier);

        return $verifier;
    }

    /**
     * @return array<string, mixed>
     */
    private static function configuration(?string $clientId = self::CLIENT, string $key = 'signing'): array
    {
        $keypair = self::keypair('op');

        return [
            'keys' => [
                // Two entries for one keypair, which is what a provider has:
                // it signs with the private half and publishes the public one.
                'signing' => ['pem_private' => $keypair['private'], 'algorithm' => 'RS256', 'kid' => 'op-2026'],
                'verify_only' => ['pem_public' => $keypair['public'], 'algorithm' => 'RS256', 'kid' => 'op-2026'],
                'api' => ['hmac' => 'a-shared-secret-of-at-least-32-bytes!'],
            ],
            'id_token_issuers' => [
                'op' => ['issuer' => self::ISSUER, 'key' => $key] + (null === $clientId ? [] : ['client_id' => $clientId]),
            ],
            'id_tokens' => [
                'self' => [
                    'issuer' => self::ISSUER,
                    'client_id' => self::CLIENT,
                    'keys' => ['verify_only'],
                    'allowed_algorithms' => ['RS256'],
                ],
            ],
            'consumers' => [
                'api' => [
                    'issuer' => self::ISSUER,
                    'audience' => self::CLIENT,
                    'keys' => ['api', 'verify_only'],
                    'allowed_algorithms' => ['HS256', 'RS256'],
                ],
            ],
        ];
    }
}
