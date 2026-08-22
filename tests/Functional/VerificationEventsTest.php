<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs512;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Event\JwtRejectedEvent;
use Medzuch\JwtBundle\Event\JwtVerifiedEvent;
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsVerification;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * What a consumer says about the tokens it is shown.
 *
 * Tokens are minted with the library directly, each broken in exactly one way,
 * so the reason a listener is handed is the reason that particular defect
 * produces — not one the test arranged by construction.
 */
#[CoversClass(AccessTokenHandler::class)]
#[CoversClass(RejectionReason::class)]
#[CoversClass(RejectedTokenException::class)]
#[CoversClass(JwtRejectedEvent::class)]
#[CoversClass(JwtVerifiedEvent::class)]
final class VerificationEventsTest extends KernelTestCase
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

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('an accepted token is announced with the claims and the identity it produced')]
    public function testVerifiedTokenIsAnnounced(): void
    {
        self::bootKernel();

        self::handler()->getUserBadgeFrom(self::token());

        $events = self::listener();
        self::assertSame([], $events->rejected);
        self::assertCount(1, $events->verified);

        $verified = $events->verified[0];
        self::assertSame('api', $verified->consumer);
        self::assertSame('user-42', $verified->identifier);
        // The token's own claims, so a listener can read anything it carries.
        self::assertSame('user-42', $verified->claims->subject());
        self::assertSame(self::ISSUER, $verified->claims->issuer());
    }

    /**
     * @param callable(): string $token
     */
    #[DataProvider('defects')]
    #[TestDox('a token that is $defect is refused as $expected->value')]
    public function testRefusalCarriesItsReason(string $defect, callable $token, RejectionReason $expected): void
    {
        self::bootKernel();

        self::refuse($token());

        $events = self::listener();
        self::assertSame([], $events->verified);
        self::assertCount(1, $events->rejected, sprintf('a token that is %s should be announced once', $defect));
        self::assertSame($expected, $events->rejected[0]->reason);
        self::assertSame('api', $events->rejected[0]->consumer);
    }

    /**
     * @return iterable<string, array{string, callable(): string, RejectionReason}>
     */
    public static function defects(): iterable
    {
        yield 'expired' => [
            'past its expiry',
            static fn(): string => self::token(expiresAt: new DateTimeImmutable('-1 minute')),
            RejectionReason::Expired,
        ];

        yield 'signature' => [
            'signed with another secret',
            static fn(): string => self::token(secret: 'a-different-secret-of-32-bytes-min!!!'),
            RejectionReason::SignatureInvalid,
        ];

        yield 'audience' => [
            'addressed to somebody else',
            static fn(): string => self::token(audience: 'https://other.test'),
            RejectionReason::WrongAudience,
        ];

        yield 'issuer' => [
            'from another issuer',
            static fn(): string => self::token(issuer: 'https://elsewhere.test'),
            RejectionReason::WrongIssuer,
        ];

        yield 'algorithm' => [
            'signed with an algorithm this consumer does not allow',
            // Its own secret, because HS512 needs 64 bytes (RFC 8725 §3.5) —
            // and it never gets that far: the algorithm is refused before any
            // signature is checked.
            static fn(): string => self::token(secret: str_repeat('a-64-byte-secret', 4), algorithm: 'HS512'),
            RejectionReason::AlgorithmRefused,
        ];

        yield 'malformed' => [
            'not a JWT at all',
            static fn(): string => 'not-a-token',
            RejectionReason::Malformed,
        ];
    }

    #[TestDox('a revoked token is refused as revoked, not as a bad token')]
    public function testRevocationHasItsOwnReason(): void
    {
        $configuration = self::configuration();
        $configuration['consumers']['api']['denylist'] = ['service' => 'test.denylist'];

        self::bootKernel(['medzuch_jwt' => $configuration]);

        $denylist = self::getContainer()->get('test.denylist');
        self::assertInstanceOf(TokenDenylistInterface::class, $denylist);
        $denylist->revoke('withdrawn', new DateTimeImmutable('+1 hour'));

        self::refuse(self::token(jwtId: 'withdrawn'));

        // Once, not twice: a refusal this bundle raises inside the parsing
        // block is caught by the block below it.
        self::assertCount(1, self::listener()->rejected);
        self::assertSame(RejectionReason::Revoked, self::listener()->rejected[0]->reason);
    }

    #[TestDox('a token addressed to more than this consumer is refused as an audience failure')]
    public function testExclusiveAudienceIsAnAudienceFailure(): void
    {
        $configuration = self::configuration();
        $configuration['consumers']['api']['audience_policy'] = 'exclusive';

        self::bootKernel(['medzuch_jwt' => $configuration]);

        // Verifies, and names somebody else as well — a refusal this bundle
        // makes rather than the library.
        self::refuse(self::token(audience: [self::AUDIENCE, 'https://reports.test']));

        self::assertCount(1, self::listener()->rejected);
        self::assertSame(RejectionReason::WrongAudience, self::listener()->rejected[0]->reason);
    }

    #[TestDox('a token the application will not turn into a user is refused as an identity failure')]
    public function testIdentityRefusalIsNotTheTokensFault(): void
    {
        $configuration = self::configuration();
        $configuration['consumers']['api']['user'] = ['mode' => 'custom', 'factory' => 'test.user_factory'];

        self::bootKernel(['medzuch_jwt' => $configuration]);

        // Verifies perfectly; the factory refuses it for naming no tenant.
        self::refuse(self::token());

        self::assertCount(1, self::listener()->rejected);
        self::assertSame(RejectionReason::IdentityRefused, self::listener()->rejected[0]->reason);
        // And nothing was announced as verified: the token was fine, the
        // request was not.
        self::assertSame([], self::listener()->verified);
    }

    #[TestDox('the reason never reaches the wire')]
    public function testTheReasonStaysBehindTheGenericMessage(): void
    {
        self::bootKernel();

        $failure = self::refuse(self::token(expiresAt: new DateTimeImmutable('-1 minute')));

        // What Symfony puts in the response is the message key, and it is the
        // same string for every refusal (RFC 6750 §3.1 has three error codes,
        // and "expired" is not one of them).
        self::assertSame('Invalid credentials.', $failure->getMessageKey());
        self::assertInstanceOf(RejectedTokenException::class, $failure);
        self::assertSame(RejectionReason::Expired, $failure->reason);
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

    private static function listener(): RecordsVerification
    {
        $listener = self::getContainer()->get('test.verification_listener');
        self::assertInstanceOf(RecordsVerification::class, $listener);

        return $listener;
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * @return array{keys: array<string, array<string, mixed>>, consumers: array<string, array<string, mixed>>}
     */
    private static function configuration(): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => [
                'api' => [
                    'issuer' => self::ISSUER,
                    'audience' => self::AUDIENCE,
                    'keys' => ['default'],
                    'allowed_algorithms' => ['HS256'],
                ],
            ],
        ];
    }

    /**
     * @param string|list<string> $audience
     */
    private static function token(
        string $secret = self::SECRET,
        string|array $audience = self::AUDIENCE,
        string $issuer = self::ISSUER,
        string $algorithm = 'HS256',
        ?DateTimeImmutable $expiresAt = null,
        ?string $jwtId = null,
    ): string {
        $profile = AccessTokenProfile::issuer(
            $issuer,
            'HS512' === $algorithm ? new Hs512() : new Hs256(),
            HmacKey::fromBinary($secret, $algorithm),
        );

        $builder = $profile->issue()
            ->subject('user-42')
            ->audience($audience)
            ->clientId('test-client');

        if (null !== $jwtId) {
            $builder = $builder->jwtId($jwtId);
        }

        $builder = null === $expiresAt
            ? $builder->expiresIn(new DateInterval('PT5M'))
            : $builder->expiresAt($expiresAt);

        return (string) $builder->build();
    }
}
