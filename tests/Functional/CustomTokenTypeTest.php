<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Security\Verification\CustomTokenVerifier;
use Medzuch\JwtBundle\Security\Verification\ProfileTokenVerifier;
use Medzuch\JwtBundle\Security\Verification\TokenVerifierInterface;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * A consumer for a `typ` this application defined.
 *
 * Every token here is minted with `JwtBuilder` rather than a profile, because
 * that is the whole point: there is no profile for a type only this application
 * knows. What the consumer keeps is everything a consumer has — keys,
 * algorithms, issuer, audience, leeway, the age ceiling, user resolution — with
 * the RFC 9068 posture's own rules replaced by the ones configured here.
 */
#[CoversClass(CustomTokenVerifier::class)]
#[CoversClass(ProfileTokenVerifier::class)]
#[CoversClass(AccessTokenHandler::class)]
final class CustomTokenTypeTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';
    private const TYPE = 'vnd.acme.session+jwt';
    private const NOW = '2026-01-01T00:00:00+00:00';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('a token of the configured type verifies and names its subject')]
    public function testTheConfiguredTypeVerifies(): void
    {
        self::bootKernel();

        $badge = self::handler()->getUserBadgeFrom(self::token());

        self::assertSame('user-42', $badge->getUserIdentifier());
    }

    #[TestDox('a consumer that names a token type is built from the validator, not from a profile')]
    public function testWhichVerifierIsBuilt(): void
    {
        self::bootKernel();
        $custom = self::verifier();

        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => self::configuration(tokenType: null)]);
        $profile = self::verifier();

        self::assertInstanceOf(CustomTokenVerifier::class, $custom);
        self::assertInstanceOf(ProfileTokenVerifier::class, $profile);
    }

    #[TestDox('a token of another type is refused, RFC 9068 included')]
    public function testAnotherTypeIsRefused(): void
    {
        self::bootKernel();

        // `at+jwt` is the type this consumer would have expected had it named
        // none. Naming one is naming *this* one.
        self::assertSame(RejectionReason::Malformed, self::refusalReason(self::token(type: 'at+jwt')));
    }

    #[TestDox('a claim the consumer requires and the token omits is a claim failure')]
    public function testARequiredClaimIsRequired(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(requiredClaims: ['exp', 'sub', 'session_id'])]);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom(self::token(claims: ['session_id' => 'abc']))->getUserIdentifier());
        self::assertSame(RejectionReason::ClaimsRefused, self::refusalReason(self::token()));
    }

    #[TestDox('exp is required unless the consumer says otherwise')]
    public function testExpiryIsTheDefaultRequirement(): void
    {
        self::bootKernel();

        // The library checks `exp` where a token carries one and nowhere else,
        // so a custom posture requiring nothing would take a credential that
        // never stops being valid.
        self::assertSame(RejectionReason::ClaimsRefused, self::refusalReason(self::token(expires: false)));
    }

    #[TestDox('an unexpiring token is accepted where an age ceiling bounds it instead')]
    public function testAnAgeCeilingCanStandInForExpiry(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(requiredClaims: ['sub'], maxTokenAge: 300)]);

        self::assertSame(
            'user-42',
            self::handler()->getUserBadgeFrom(self::token(expires: false, issuedAt: '-4 minutes'))->getUserIdentifier(),
        );

        self::assertSame(RejectionReason::TooOld, self::refusalReason(self::token(expires: false, issuedAt: '-6 minutes')));
    }

    #[TestDox('an age ceiling on a token carrying no iat refuses rather than exempts it')]
    public function testTheCeilingNeedsAnIssuingTime(): void
    {
        // The branch no profile can reach: all three of the library's require
        // `iat`, and a type this application defined need not.
        self::bootKernel(['medzuch_jwt' => self::configuration(maxTokenAge: 300)]);

        $failure = self::refuse(self::token(issuedAt: null));

        self::assertInstanceOf(RejectedTokenException::class, $failure);
        self::assertSame(RejectionReason::ClaimsRefused, $failure->reason);
        self::assertStringContainsString('carries no "iat"', $failure->getMessage());
    }

    #[TestDox('the rest of a consumer is unchanged: issuer, audience and keys still decide')]
    public function testTheRestOfTheConsumerStillApplies(): void
    {
        self::bootKernel();

        self::assertSame(RejectionReason::WrongIssuer, self::refusalReason(self::token(issuer: 'https://elsewhere.test')));
        self::assertSame(RejectionReason::WrongAudience, self::refusalReason(self::token(audience: 'https://other.test')));
        self::assertSame(RejectionReason::SignatureInvalid, self::refusalReason(self::token(secret: 'another-secret-of-at-least-32-by!!!!')));
    }

    #[TestDox('required_claims without a token_type fails at container build')]
    public function testRequiredClaimsNeedAType(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('lists "required_claims" without a "token_type"');

        self::bootKernel(['medzuch_jwt' => self::configuration(tokenType: null, requiredClaims: ['exp'])]);
    }

    #[TestDox('a token type carrying the application/ prefix fails at container build')]
    public function testThePrefixIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('drop the "application/" prefix');

        self::bootKernel(['medzuch_jwt' => self::configuration(tokenType: 'application/vnd.acme.session+jwt')]);
    }

    #[TestDox('a list that drops exp without bounding the age fails at container build')]
    public function testSomethingHasToBoundTheToken(): void
    {
        // The realistic version of the mistake: a list written for what the
        // application's own token carries, with the expiry forgotten.
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('need never stop being valid');

        self::bootKernel(['medzuch_jwt' => self::configuration(requiredClaims: ['sub', 'session_id'])]);
    }

    private static function refusalReason(string $token): RejectionReason
    {
        $failure = self::refuse($token);

        self::assertInstanceOf(RejectedTokenException::class, $failure);

        return $failure->reason;
    }

    private static function refuse(string $token): AuthenticationException
    {
        try {
            self::handler()->getUserBadgeFrom($token);
        } catch (AuthenticationException $failure) {
            return $failure;
        }

        self::fail('the token should have been refused');
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    private static function verifier(): TokenVerifierInterface
    {
        $verifier = self::getContainer()->get('medzuch_jwt.verifier.api');
        self::assertInstanceOf(TokenVerifierInterface::class, $verifier);

        return $verifier;
    }

    /**
     * @param list<string>|null $requiredClaims
     *
     * @return array<string, mixed>
     */
    private static function configuration(
        ?string $tokenType = self::TYPE,
        ?array $requiredClaims = null,
        ?int $maxTokenAge = null,
    ): array {
        $consumer = [
            'issuer' => self::ISSUER,
            'audience' => self::AUDIENCE,
            'keys' => ['default'],
            'allowed_algorithms' => ['HS256'],
        ];

        if (null !== $tokenType) {
            $consumer['token_type'] = $tokenType;
        }

        if (null !== $requiredClaims) {
            $consumer['required_claims'] = $requiredClaims;
        }

        if (null !== $maxTokenAge) {
            $consumer['max_token_age'] = $maxTokenAge;
        }

        return [
            'clock' => 'test.frozen_clock',
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => $consumer],
        ];
    }

    /**
     * @param string|list<string>  $audience
     * @param array<string, mixed> $claims
     */
    private static function token(
        string $type = self::TYPE,
        string $secret = self::SECRET,
        string $issuer = self::ISSUER,
        string|array $audience = self::AUDIENCE,
        bool $expires = true,
        ?string $issuedAt = '-1 minute',
        array $claims = [],
    ): string {
        $now = new DateTimeImmutable(self::NOW);

        $builder = JwtBuilder::create(FrozenClock::at(self::NOW))
            ->type($type)
            ->issuer($issuer)
            ->subject('user-42')
            ->audience($audience);

        if (null !== $issuedAt) {
            $moment = $now->modify($issuedAt);

            self::assertNotFalse($moment);

            $builder = $builder->issuedAt($moment);
        }

        if ($expires) {
            $builder = $builder->expiresIn(new DateInterval('PT1H'));
        }

        foreach ($claims as $claim => $value) {
            $builder = $builder->withClaim($claim, $value);
        }

        return (string) $builder->signWith(new Hs256(), HmacKey::fromBinary($secret, 'HS256'))->build();
    }
}
