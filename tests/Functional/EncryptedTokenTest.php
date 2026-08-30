<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\Encryption\A128Gcm;
use Medzuch\Jwt\Algorithm\Encryption\A256CbcHs512;
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A128Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\KeyManagement\Dir;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jwe\Encrypter;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Jwt\NestedJwtBuilder;
use Medzuch\Jwt\Jwt\NestedJwtParser;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Security\Verification\NestedTokenVerifier;
use Medzuch\JwtBundle\Tests\Functional\App\InMemoryDenylist;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsVerification;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use ReflectionClass;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Consuming an encrypted token: a JWE wrapping the signed JWT this consumer
 * would otherwise have been handed directly (C12, RFC 7519 §5.2).
 *
 * Two claims run through the whole file. The first is that the outer layer is
 * really opened — a token sealed to a key this consumer does not hold, or with
 * an algorithm it does not allow, gets no further than the ciphertext. The
 * second is that opening it changes nothing else: the issuer, audience, expiry
 * and profile of the token inside are judged by the same consumer that judges
 * an unencrypted one, so an expired token in a perfectly good envelope is
 * still expired.
 *
 * Nothing here mints an encrypted token through the bundle, because nothing in
 * the bundle does yet: I8 is the other half, and until it lands the tokens are
 * built with the library directly — which is also how a third party's would
 * arrive.
 */
#[CoversClass(NestedTokenVerifier::class)]
final class EncryptedTokenTest extends WebTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';

    /** Exactly 32 bytes, which is what A256KW is and what A256GCM needs of a `dir` key. */
    private const WRAPPING = '0123456789abcdef0123456789abcdef';

    private const KID = 'enc-2026';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();
        $config = is_array($config) ? $config : [];

        // One case wants a real firewall in front of a real controller; the
        // rest ask the handler directly, where a refusal carries the reason
        // the wire deliberately does not.
        return ($options['firewall'] ?? false) === true ? new SecuredKernel($config) : new TestKernel($config);
    }

    #[TestDox('an encrypted token authenticates through a real firewall')]
    public function testEncryptedBearerAuthenticates(): void
    {
        $client = self::createClient(['firewall' => true]);

        // The subject is the one name SecuredKernel's in-memory provider
        // knows: the default mode asks the application's store who this is,
        // and encryption does not change that half either.
        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . self::sealed(self::signed(subject: 'alice'))]);

        self::assertResponseIsSuccessful();
        self::assertSame('alice', self::json($client)['user'] ?? null);
    }

    #[TestDox('the token inside is what the consumer ends up reading')]
    public function testTheClaimsComeFromInside(): void
    {
        self::bootKernel();

        self::assertSame('user-42', self::handler()->getUserBadgeFrom(self::sealed(self::signed()))->getUserIdentifier());

        $verified = self::listener()->verified;
        self::assertCount(1, $verified);
        self::assertSame(self::ISSUER, $verified[0]->claims->issuer());
    }

    /**
     * The reason the `jwe` block has no "accept either" mode. A consumer that
     * took the signed token on its own would let anyone who can strip two dots
     * decide that these claims travel in the clear.
     */
    #[TestDox('the same token with its encryption stripped off is refused')]
    public function testStrippedEncryptionIsRefused(): void
    {
        self::bootKernel();

        $signed = self::signed();

        self::assertSame('user-42', self::handler()->getUserBadgeFrom(self::sealed($signed))->getUserIdentifier());
        self::assertSame(RejectionReason::Malformed, self::refusal($signed));
    }

    /**
     * @param callable(): string $token
     */
    #[DataProvider('unopenable')]
    #[TestDox('a token $defect is refused as $expected->value')]
    public function testRefusalsCarryTheirReason(string $defect, callable $token, RejectionReason $expected): void
    {
        self::bootKernel();

        self::assertSame($expected, self::refusal($token()), $defect);
        self::assertSame([], self::listener()->verified);
    }

    /**
     * @return iterable<string, array{string, callable(): string, RejectionReason}>
     */
    public static function unopenable(): iterable
    {
        yield 'another key' => [
            'sealed to a key this consumer does not hold',
            static fn(): string => self::sealed(self::signed(), key: OctKey::fromBinary(strrev(self::WRAPPING), 'A256KW', self::KID)),
            RejectionReason::DecryptionFailed,
        ];

        yield 'unknown kid' => [
            'naming an encryption key this consumer has never heard of',
            static fn(): string => self::sealed(self::signed(), key: OctKey::fromBinary(self::WRAPPING, 'A256KW', 'enc-1999')),
            RejectionReason::UnknownKey,
        ];

        yield 'tampered' => [
            'whose ciphertext was altered after it was written',
            static fn(): string => self::tamper(self::sealed(self::signed())),
            RejectionReason::DecryptionFailed,
        ];

        yield 'key management' => [
            'wrapped with an algorithm this consumer does not allow',
            static fn(): string => self::sealed(self::signed(), key: OctKey::fromBinary(substr(self::WRAPPING, 0, 16), 'A128KW', self::KID), keyManagement: new A128Kw()),
            RejectionReason::AlgorithmRefused,
        ];

        yield 'content encryption' => [
            'whose content is encrypted with an algorithm this consumer does not allow',
            static fn(): string => self::sealed(self::signed(), contentEncryption: new A256CbcHs512()),
            RejectionReason::AlgorithmRefused,
        ];

        yield 'no content type' => [
            'whose outer header does not say a JWT is inside',
            static fn(): string => self::encrypted(self::signed(), ['kid' => self::KID]),
            RejectionReason::Malformed,
        ];

        yield 'wrong content type' => [
            'whose outer header says something other than a JWT is inside',
            static fn(): string => self::encrypted(self::signed(), ['kid' => self::KID, 'cty' => 'application/json']),
            RejectionReason::Malformed,
        ];

        yield 'not a jwt inside' => [
            'that decrypts to something which is not a JWT at all',
            static fn(): string => self::encrypted('nothing.like.a-token', ['kid' => self::KID, 'cty' => 'JWT']),
            RejectionReason::Malformed,
        ];

        yield 'json serialization' => [
            'serialized as JSON, which no Authorization header carries',
            static fn(): string => json_encode((new Encrypter())->encryptFlattened(
                new A256Kw(),
                new A256Gcm(),
                ['kid' => self::KID, 'cty' => 'JWT'],
                self::signed(),
                OctKey::fromBinary(self::WRAPPING, 'A256KW', self::KID),
            ), \JSON_THROW_ON_ERROR),
            RejectionReason::Malformed,
        ];

        yield 'replicated issuer' => [
            'whose outer header repeats an issuer the token inside disagrees with',
            static fn(): string => self::sealed(self::signed(), ['iss' => 'https://elsewhere.test']),
            RejectionReason::Malformed,
        ];

        yield 'expired inside' => [
            'that opens perfectly and has expired',
            static fn(): string => self::sealed(self::signed(expiresAt: new DateTimeImmutable('-1 minute'))),
            RejectionReason::Expired,
        ];
    }

    /**
     * The claim the decorator makes, at the three places it would be easiest to
     * have quietly lost: the checks the handler runs *after* the library is
     * finished with the token. An expired token proves the library's own half
     * still runs; these prove the bundle's does.
     *
     * @param array<string, mixed>                  $consumer
     * @param callable(): string                    $token
     */
    #[DataProvider('innerPostures')]
    #[TestDox('a sealed token is still judged by the consumer\'s $posture')]
    public function testThePostureBehindTheEnvelopeStillRuns(string $posture, array $consumer, callable $token, RejectionReason $expected): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(consumer: $consumer)]);

        self::assertSame($expected, self::refusal($token()), $posture);
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, callable(): string, RejectionReason}>
     */
    public static function innerPostures(): iterable
    {
        yield 'exclusive audience' => [
            'exclusive audience policy',
            ['audience_policy' => 'exclusive'],
            static fn(): string => self::sealed(self::signed(audience: [self::AUDIENCE, 'https://other.test'])),
            RejectionReason::WrongAudience,
        ];

        yield 'max token age' => [
            'ceiling on how old a token may be',
            ['max_token_age' => 60],
            static fn(): string => self::sealed(self::signed(issuedAt: new DateTimeImmutable('-2 hours'), expiresAt: new DateTimeImmutable('+2 hours'))),
            RejectionReason::TooOld,
        ];

        yield 'denylist' => [
            'denylist',
            ['denylist' => ['service' => 'test.denylist']],
            static function (): string {
                $denylist = self::getContainer()->get('test.denylist');
                self::assertInstanceOf(InMemoryDenylist::class, $denylist);
                $denylist->revoke('withdrawn', new DateTimeImmutable('+1 hour'));

                return self::sealed(self::signed(jwtId: 'withdrawn'));
            },
            RejectionReason::Revoked,
        ];
    }

    /**
     * RFC 7515 §4.1.9 makes the `application/` prefix optional on the wire, so
     * the prefixed spelling of the same media type is the same answer. The
     * comparison is the library's own, which is why the mixed-case prefixed
     * form is not asserted here: `MediaType::equivalent()` lowercases the
     * whole value on one branch and only the prefix on the other, so
     * `application/JWT` and `JWT` come out unequal — medzuch/jwt-php#62. This
     * asserts the spelling that behaves; a second implementation of media-type
     * comparison in this bundle would be the wrong fix.
     */
    #[TestDox('"application/jwt" says the same thing as "JWT"')]
    public function testContentTypeIsComparedAsAMediaType(): void
    {
        self::bootKernel();

        $token = self::encrypted(self::signed(), ['kid' => self::KID, 'cty' => 'application/jwt']);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * RFC 7519 §5.3 constrains a replicated claim to agree, and constrains
     * nothing else: a sender that repeats `iss` so an intermediary can route
     * without holding a key is doing what the section is for.
     */
    #[TestDox('an outer header repeating a claim that agrees is accepted')]
    public function testReplicatedClaimsMayAgree(): void
    {
        self::bootKernel();

        $token = self::sealed(self::signed(), ['iss' => self::ISSUER]);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * §5.3 is about claims a sender deliberately repeated, and a JOSE header
     * parameter is not one: an inner claim that happens to be called `kid` has
     * nothing to do with the outer `kid` that said which key to decrypt with.
     * Compared anyway, the two would disagree and a token would be refused for
     * agreeing with itself.
     */
    #[TestDox('a claim sharing a JOSE header parameter name is not compared against it')]
    public function testJoseParameterNamesAreNotClaims(): void
    {
        self::bootKernel();

        $token = self::sealed(self::signed(claims: ['kid' => 'a claim of our own', 'typ' => 'not a media type']));

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * The decorator wraps whichever verifier the consumer was going to get, so
     * a posture assembled from the lower-level API gets encryption on the same
     * terms as the RFC 9068 one — and keeps its own `typ`, which is the part a
     * shared decorator could plausibly have lost.
     */
    #[TestDox('a consumer with a token_type of its own decrypts too')]
    public function testCustomTokenTypeDecrypts(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(consumer: ['token_type' => 'vnd.acme.session+jwt'])]);

        $custom = (string) JwtBuilder::create()
            ->type('vnd.acme.session+jwt')
            ->issuer(self::ISSUER)
            ->subject('user-42')
            ->audience(self::AUDIENCE)
            ->expiresAt(new DateTimeImmutable('+5 minutes'))
            ->signWith(new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'))
            ->build();

        self::assertSame('user-42', self::handler()->getUserBadgeFrom(self::sealed($custom))->getUserIdentifier());

        // The token inside is still held to this consumer's own type: an
        // access token in the same envelope is the wrong kind of token.
        self::assertSame(RejectionReason::Malformed, self::refusal(self::sealed(self::signed())));
    }

    /**
     * The skip list is a copy of the one inside the library's own nested
     * parser, and a copy is only safe while it stays a copy. Reflection rather
     * than a second reading of the RFCs: what matters is that the two agree,
     * and drift shows up in production as a token refused for agreeing with
     * itself, which is a hard sentence to arrive at from a stack trace.
     *
     * Skipped rather than failed if the upstream const is renamed or made
     * public — that is a change to somebody else's private API, not a defect
     * here, and a red suite would say the wrong thing about it.
     */
    #[TestDox('the JOSE header parameters skipped here are the ones the library skips')]
    public function testTheSkipListHasNotDriftedFromTheLibrary(): void
    {
        $upstream = new ReflectionClass(NestedJwtParser::class);

        if (!$upstream->hasConstant('JOSE_HEADER_PARAMETERS')) {
            self::markTestSkipped('the library no longer keeps this list under that name');
        }

        $ours = new ReflectionClass(NestedTokenVerifier::class);

        self::assertSame(
            $upstream->getConstant('JOSE_HEADER_PARAMETERS'),
            $ours->getConstant('JOSE_HEADER_PARAMETERS'),
            'the RFC 7519 §5.3 skip list has drifted from the library\'s',
        );
    }

    /**
     * §5.3 constrains a claim that was *repeated*, which means present on both
     * sides. A name in the outer header alone is not a disagreement, and it is
     * not treated as one — a JWE protected header is also where a sender puts
     * things that were never claims, and refusing those would refuse tokens the
     * RFCs allow. The library's own nested parser draws the line in the same
     * place.
     */
    #[TestDox('a header name with no claim of that name inside is not a disagreement')]
    public function testHeaderNamesWithNoClaimAreNotCompared(): void
    {
        self::bootKernel();

        $token = self::sealed(self::signed(), ['routing_hint' => 'eu-west']);

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    #[TestDox('direct encryption reaches its key by kid')]
    public function testDirectEncryption(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration([
            'keys' => ['sealed'],
            'allowed_key_management' => ['dir'],
            'allowed_content_encryption' => ['A256GCM'],
        ], ['sealed' => ['secret' => self::WRAPPING, 'algorithm' => 'A256GCM', 'kid' => self::KID]])]);

        $token = self::sealed(
            self::signed(),
            key: OctKey::fromBinary(self::WRAPPING, 'A256GCM', self::KID),
            keyManagement: new Dir(),
        );

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * The other side of the rule that refuses a content algorithm with no key
     * behind it: a key that *wraps* one wraps it for any content algorithm
     * going, so a consumer allowing a wrapping scheme beside `dir` may allow a
     * content algorithm no `dir` key names — and a token using that pair opens.
     */
    #[TestDox('a wrapping key covers a content algorithm no direct key is bound to')]
    public function testWrappingCoversEveryContentAlgorithm(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(
            [
                'keys' => ['sealed', 'direct'],
                'allowed_key_management' => ['dir', 'A256KW'],
                'allowed_content_encryption' => ['A256GCM', 'A128GCM'],
            ],
            [
                'sealed' => ['secret' => self::WRAPPING, 'algorithm' => 'A256KW', 'kid' => self::KID],
                'direct' => ['secret' => self::WRAPPING, 'algorithm' => 'A256GCM', 'kid' => 'dir-1'],
            ],
        )]);

        // A128GCM has no key of its own: the wrapped Content Encryption Key is
        // generated per token, and the configured key only unwraps it.
        $token = self::sealed(self::signed(), contentEncryption: new A128Gcm());

        self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * The same shape rotation has everywhere else in this bundle: accept both,
     * then ask the sender to move. The `kid` in the outer header is what makes
     * the second key reachable while the first is still configured.
     */
    #[TestDox('a second encryption key is accepted beside the first')]
    public function testRotation(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(
            ['keys' => ['sealed', 'next'], 'allowed_key_management' => ['A256KW'], 'allowed_content_encryption' => ['A256GCM']],
            [
                'sealed' => ['secret' => self::WRAPPING, 'algorithm' => 'A256KW', 'kid' => self::KID],
                'next' => ['secret' => strrev(self::WRAPPING), 'algorithm' => 'A256KW', 'kid' => 'enc-2027'],
            ],
        )]);

        foreach ([self::KID => self::WRAPPING, 'enc-2027' => strrev(self::WRAPPING)] as $kid => $secret) {
            $token = self::sealed(self::signed(), key: OctKey::fromBinary($secret, 'A256KW', $kid));

            self::assertSame('user-42', self::handler()->getUserBadgeFrom($token)->getUserIdentifier(), $kid);
        }
    }

    /**
     * @param array<string, mixed> $outerHeader
     */
    private static function sealed(
        string $signed,
        array $outerHeader = [],
        ?OctKey $key = null,
        ?KeyManagementAlgorithm $keyManagement = null,
        ?ContentEncryptionAlgorithm $contentEncryption = null,
    ): string {
        $key ??= OctKey::fromBinary(self::WRAPPING, 'A256KW', self::KID);

        return (string) NestedJwtBuilder::wrap(
            new CompactJws($signed),
            $keyManagement ?? new A256Kw(),
            $contentEncryption ?? new A256Gcm(),
            $key,
            $outerHeader + ['kid' => $key->kid()],
        );
    }

    /**
     * The layer below {@see self::sealed()}, for the headers a nested-JWT
     * helper will not write: no `cty` at all, or one naming something else.
     *
     * @param array<string, mixed> $outerHeader
     */
    private static function encrypted(string $plaintext, array $outerHeader): string
    {
        return (string) (new Encrypter())->encrypt(
            new A256Kw(),
            new A256Gcm(),
            $outerHeader,
            $plaintext,
            OctKey::fromBinary(self::WRAPPING, 'A256KW', self::KID),
        );
    }

    /**
     * The first character of the ciphertext, which the AEAD tag covers.
     *
     * The first rather than any: base64url's last character carries fewer than
     * six meaningful bits, and the decoder is strict about the padding ones
     * being zero — so altering the end of a segment makes a token that will
     * not decode rather than one that will not authenticate, which is a
     * different refusal than the one this is here to provoke.
     */
    private static function tamper(string $compact): string
    {
        $segments = explode('.', $compact);
        $segments[3] = ('A' === $segments[3][0] ? 'B' : 'A') . substr($segments[3], 1);

        return implode('.', $segments);
    }

    /**
     * @param array<string, mixed>          $claims
     * @param string|non-empty-list<string> $audience
     */
    private static function signed(
        ?DateTimeImmutable $expiresAt = null,
        string $subject = 'user-42',
        array $claims = [],
        string|array $audience = self::AUDIENCE,
        ?DateTimeImmutable $issuedAt = null,
        ?string $jwtId = null,
    ): string {
        // Dated by a clock of its own where the case needs an `iat` in the
        // past: `max_token_age` reads that claim, and a token minted now is
        // never too old however generous the ceiling.
        $clock = null === $issuedAt ? null : FrozenClock::at($issuedAt->format(DATE_ATOM));

        $builder = AccessTokenProfile::issuer(self::ISSUER, new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'), $clock)
            ->issue()
            ->subject($subject)
            ->audience($audience)
            ->clientId('test-client')
            ->jwtId($jwtId ?? bin2hex(random_bytes(8)));

        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return (string) (null === $expiresAt ? $builder->expiresIn(new DateInterval('PT300S')) : $builder->expiresAt($expiresAt))->build();
    }

    /**
     * @param array{keys: list<string>, allowed_key_management: list<string>, allowed_content_encryption: list<string>}|null $jwe
     * @param array<string, array{secret: string, algorithm: string, kid?: string}>|null                                    $jweKeys
     * @param array<string, mixed>                                                                                          $consumer options this consumer sets on top of the defaults below
     *
     * @return array<string, mixed>
     */
    private static function configuration(?array $jwe = null, ?array $jweKeys = null, array $consumer = []): array
    {
        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'jwe_keys' => $jweKeys ?? ['sealed' => ['secret' => self::WRAPPING, 'algorithm' => 'A256KW', 'kid' => self::KID]],
            'consumers' => ['api' => $consumer + [
                'issuer' => self::ISSUER,
                'audience' => self::AUDIENCE,
                'keys' => ['default'],
                'allowed_algorithms' => ['HS256'],
                'jwe' => $jwe ?? [
                    'keys' => ['sealed'],
                    'allowed_key_management' => ['A256KW'],
                    'allowed_content_encryption' => ['A256GCM'],
                ],
            ]],
        ];
    }

    private static function refusal(string $token): RejectionReason
    {
        try {
            self::handler()->getUserBadgeFrom($token);
        } catch (RejectedTokenException $failure) {
            return $failure->reason;
        }

        self::fail('the token should have been refused');
    }

    private static function handler(): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.api');
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    private static function listener(): RecordsVerification
    {
        $listener = self::getContainer()->get('test.verification_listener');
        self::assertInstanceOf(RecordsVerification::class, $listener);

        return $listener;
    }

    /**
     * @return array<string, mixed>
     */
    private static function json(KernelBrowser $client): array
    {
        $decoded = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertSame(Response::HTTP_OK, $client->getResponse()->getStatusCode());

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
