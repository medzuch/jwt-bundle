<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Exception\InvalidClaimException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Profile\IdTokenProfile;
use Medzuch\JwtBundle\Oidc\IdTokenVerifier;
use Medzuch\JwtBundle\Tests\Functional\App\OidcCallback;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * ID tokens from an identity provider, verified for one client registration.
 *
 * The provider is played by the library's own issuing side with a keypair
 * generated per run, so the tokens under test are ones a real provider would
 * mint rather than fixtures shaped to pass.
 */
#[CoversClass(IdTokenVerifier::class)]
final class IdTokenTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const ISSUER = 'https://idp.test';

    private const CLIENT = 'client-42';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('an ID token from the registered provider verifies, and its claims come back')]
    public function testVerifies(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $claims = self::verifier()->verify(self::idToken());

        self::assertSame('user-42', $claims->getString('sub'));
        self::assertSame(self::ISSUER, $claims->getString('iss'));
    }

    #[TestDox('the nonce bound to the authentication request is checked when given')]
    public function testNonceMatches(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $claims = self::verifier()->verify(self::idToken(nonce: 'n-0S6_WzA2Mj'), 'n-0S6_WzA2Mj');

        self::assertSame('user-42', $claims->getString('sub'));
    }

    #[TestDox('a token carrying another authentication request\'s nonce is refused')]
    public function testNonceMismatch(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/"nonce" does not match/');

        self::verifier()->verify(self::idToken(nonce: 'replayed'), 'n-0S6_WzA2Mj');
    }

    #[TestDox('a token minted for another client is refused')]
    public function testWrongClient(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $this->expectException(JwtException::class);

        self::verifier()->verify(self::idToken(audience: 'someone-else'));
    }

    #[TestDox('a token with several audiences and no azp is refused (OIDC Core §3.1.3.7)')]
    public function testMultipleAudiencesWithoutAzp(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessageMatches('/multiple audiences but no "azp"/');

        self::verifier()->verify(self::idToken(audience: [self::CLIENT, 'another-client']));
    }

    #[TestDox('several audiences are fine once azp names this client')]
    public function testMultipleAudiencesWithAzp(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $claims = self::verifier()->verify(self::idToken(audience: [self::CLIENT, 'another-client'], azp: self::CLIENT));

        self::assertSame('user-42', $claims->getString('sub'));
    }

    #[TestDox('a token signed with a key the provider does not publish is refused')]
    public function testUnknownKey(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $this->expectException(JwtException::class);

        self::verifier()->verify(self::idToken(pem: self::freshKeypair()['private']));
    }

    #[TestDox('the verifier arrives by argument name, so a controller need not know service ids')]
    public function testAutowiringByRegistrationName(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $callback = self::getContainer()->get('test.oidc_callback');
        self::assertInstanceOf(OidcCallback::class, $callback);
        self::assertSame(self::verifier(), $callback->partner, 'IdTokenVerifier $partner should be the "partner" registration');
    }

    #[TestDox('a registration with nothing to verify with fails at container build')]
    public function testRegistrationWithoutKeys(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/ID token registration "partner" has nothing to verify with/');

        self::bootKernel(['medzuch_jwt' => self::configuration(keys: [])]);
    }

    #[TestDox('a registration naming a key that does not exist fails at container build')]
    public function testRegistrationWithUnknownKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/ID token registration "partner" names key "typo"/');

        self::bootKernel(['medzuch_jwt' => self::configuration(keys: ['typo'])]);
    }

    #[TestDox('no ID token registration means no verifier, not an idle one')]
    public function testNoRegistrationMeansNoService(): void
    {
        self::bootKernel(['medzuch_jwt' => ['keys' => ['idp' => ['pem_public' => self::keypair('idp')['public'], 'algorithm' => 'RS256', 'kid' => 'idp-2026']]]]);

        self::assertFalse(self::getContainer()->has('medzuch_jwt.id_token.partner'));
    }

    /**
     * @param string|list<string> $audience
     */
    private static function idToken(string|array $audience = self::CLIENT, ?string $nonce = null, ?string $azp = null, ?string $pem = null): string
    {
        $profile = IdTokenProfile::issuer(
            self::ISSUER,
            new Rs256(),
            RsaPrivateKey::fromPem($pem ?? self::keypair('idp')['private'], 'RS256', 'idp-2026'),
        );

        $builder = $profile->issue()
            ->subject('user-42')
            ->audience($audience)
            ->expiresIn(new \DateInterval('PT5M'));

        if (null !== $nonce) {
            $builder = $builder->nonce($nonce);
        }

        if (null !== $azp) {
            $builder = $builder->authorizedParty($azp);
        }

        return (string) $builder->build();
    }

    private static function verifier(): IdTokenVerifier
    {
        $verifier = self::getContainer()->get('medzuch_jwt.id_token.partner');
        self::assertInstanceOf(IdTokenVerifier::class, $verifier);

        return $verifier;
    }

    /**
     * @param list<string> $keys names the registration verifies with
     *
     * @return array<string, mixed>
     */
    private static function configuration(array $keys = ['idp']): array
    {
        return [
            'keys' => [
                'idp' => ['pem_public' => self::keypair('idp')['public'], 'algorithm' => 'RS256', 'kid' => 'idp-2026'],
            ],
            'id_tokens' => [
                'partner' => [
                    'issuer' => self::ISSUER,
                    'client_id' => self::CLIENT,
                    'keys' => $keys,
                    'allowed_algorithms' => ['RS256'],
                ],
            ],
        ];
    }
}
