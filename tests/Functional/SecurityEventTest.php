<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use DateInterval;
use Medzuch\Jwt\Algorithm\Signing\Rs256;
use Medzuch\Jwt\Exception\ClaimTypeException;
use Medzuch\Jwt\Exception\InvalidClaimException;
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Key\RsaPrivateKey;
use Medzuch\Jwt\Profile\IdTokenProfile;
use Medzuch\JwtBundle\SecurityEvent\SecurityEventIssuer;
use Medzuch\JwtBundle\SecurityEvent\SecurityEventVerifier;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * RFC 8417 Security Event Tokens, both halves (C8, I7): a transmitter minting
 * an event and a receiver accepting it.
 *
 * The two are configured against one keypair and exercised end to end rather
 * than each against a fixture, because the thing worth asserting is that they
 * agree — a transmitter stamping a type the receiver does not require, or a
 * receiver pinning an audience the transmitter never names, is exactly the
 * failure a pair of one-sided tests would each pass.
 *
 * What is *not* here is a firewall. A SET authenticates nobody: it says
 * something happened to a subject who is not the caller, so it reaches the
 * application through a controller rather than a token handler, and these rows
 * call the services the way that controller would.
 */
#[CoversClass(SecurityEventIssuer::class)]
#[CoversClass(SecurityEventVerifier::class)]
final class SecurityEventTest extends KernelTestCase
{
    use GeneratesKeypairs;
    use RestoresExceptionHandler;

    private const ISSUER = 'https://idp.test';

    private const RECEIVER = 'https://rp.test';

    /** One of the RISC event URIs, which is what a real stream carries. */
    private const ACCOUNT_DISABLED = 'https://schemas.openid.net/secevent/risc/event-type/account-disabled';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('an event this application transmits is one it can receive back')]
    public function testRoundTrip(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $set = self::transmitter()->issue()
            ->subject('user-42')
            ->event(self::ACCOUNT_DISABLED, ['reason' => 'hijacking'])
            ->build();

        $claims = self::receiver()->verify((string) $set);

        self::assertSame(self::ISSUER, $claims->getString('iss'));
        self::assertSame('user-42', $claims->getString('sub'));
        self::assertSame(['reason' => 'hijacking'], self::events($claims)[self::ACCOUNT_DISABLED]);
    }

    #[TestDox('the profile stamps the claims RFC 8417 §2.2 requires without being asked')]
    public function testRequiredClaimsAreFilledIn(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $claims = self::receiver()->verify((string) self::anEvent());

        // `jti` is the one that matters most here: it is what a receiver
        // deduplicates on, and a SET has no `exp` to make replay expire.
        $jti = $claims->jwtId();

        self::assertIsString($jti);
        self::assertNotSame('', $jti);
        self::assertNotNull($claims->issuedAt());
    }

    #[TestDox('a SET carries no expiry, because an event is not a credential')]
    public function testNoExpiry(): void
    {
        // RFC 8417 §4.1.4. Asserted rather than assumed because the absence is
        // load-bearing: it is why the README tells a receiver to deduplicate on
        // `jti`, and a profile that started stamping `exp` would quietly make
        // that advice look optional.
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        self::assertFalse(self::receiver()->verify((string) self::anEvent())->has('exp'));
    }

    #[TestDox('the configured audience is the one every event from the stream names')]
    public function testConfiguredAudienceIsStamped(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $claims = self::receiver()->verify((string) self::anEvent());

        self::assertSame([self::RECEIVER], $claims->audience());
    }

    #[TestDox('an event addressed to somebody else is refused')]
    public function testAudienceIsChecked(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        // Overriding the stream's audience on one SET, which is the shape of
        // the mistake worth catching: a transmitter feeding several receivers
        // and naming the wrong one.
        $set = self::transmitter()->issue()
            ->audience('https://someone-else.test')
            ->event(self::ACCOUNT_DISABLED)
            ->build();

        $this->expectException(JwtException::class);

        self::receiver()->verify((string) $set);
    }

    #[TestDox('an event from an issuer this receiver does not know is refused')]
    public function testIssuerIsPinned(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(issuer: 'https://attacker.test')]);

        $this->expectException(JwtException::class);

        self::receiver()->verify((string) self::anEvent());
    }

    #[TestDox('an access token is not a security event, whatever it is signed with')]
    public function testAnAccessTokenIsRefused(): void
    {
        // The same key, the same issuer, the same algorithm — and refused, on
        // `typ`. Without this row the receiver would look like it accepted any
        // token this application mints, which is what an explicit-typing
        // posture exists to prevent (RFC 8725 §3.11).
        self::bootKernel(['medzuch_jwt' => self::configuration() + [
            'issuers' => ['default' => [
                'issuer' => self::ISSUER,
                'key' => 'stream',
                'client_id' => 'test-client',
                'audience' => self::RECEIVER,
            ]],
        ]]);

        $issuer = self::getContainer()->get('medzuch_jwt.issuer.default');
        self::assertInstanceOf(\Medzuch\JwtBundle\Issuer\AccessTokenIssuer::class, $issuer);

        $this->expectException(JwtException::class);

        self::receiver()->verify($issuer->issue('user-42')->value);
    }

    #[TestDox('a token declaring no events is refused as a security event')]
    public function testEventsMustBePresent(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        // Built through the library's lower-level path, because the builder
        // this bundle hands out refuses to produce one: `events` is what makes
        // a SET a SET, and the receiver has to refuse it too rather than trust
        // that every transmitter uses a builder as careful as ours.
        $set = self::transmitter()->issue()
            ->event(self::ACCOUNT_DISABLED)
            ->withClaim('events', [])
            ->build();

        $this->expectException(InvalidClaimException::class);

        self::receiver()->verify((string) $set);
    }

    #[TestDox('an events claim that is a JSON array rather than an object is refused')]
    public function testEventsMustBeAnObject(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $set = self::transmitter()->issue()
            ->event(self::ACCOUNT_DISABLED)
            ->withClaim('events', [self::ACCOUNT_DISABLED])
            ->build();

        $this->expectException(InvalidClaimException::class);

        self::receiver()->verify((string) $set);
    }

    #[TestDox('an events claim that is not a structure at all is refused')]
    public function testEventsMustBeAStructure(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $set = self::transmitter()->issue()
            ->event(self::ACCOUNT_DISABLED)
            ->withClaim('events', 'account-disabled')
            ->build();

        $this->expectException(ClaimTypeException::class);

        self::receiver()->verify((string) $set);
    }

    #[TestDox('a stream with no configured audience leaves `aud` to the caller')]
    public function testAudienceIsOptionalOnTheStream(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(addressed: false)]);

        $claims = self::receiver()->verify((string) self::anEvent());

        self::assertSame([], $claims->audience());
    }

    #[TestDox('an event carrying several kinds is delivered whole')]
    public function testSeveralEvents(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $second = 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise';

        $set = self::transmitter()->issue()
            ->event(self::ACCOUNT_DISABLED, ['reason' => 'hijacking'])
            ->event($second)
            ->build();

        $events = self::events(self::receiver()->verify((string) $set));

        self::assertSame([self::ACCOUNT_DISABLED, $second], array_keys($events));
        // An event with no payload is `{}` on the wire and an empty structure
        // here — never a JSON array, which would fail the receiver's own check.
        self::assertSame([], $events[$second]);
    }

    #[TestDox('the minted token declares the type the receiver pins')]
    public function testIssuedTypeIsStamped(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        // The transmitter's half of the refusal below: `typ` is what separates
        // a SET from every other token this application signs with the same
        // key, so asserting the header makes both sides of that explicit.
        // Read through the library's parser rather than by decoding base64url
        // here, which would be a second implementation of the one thing the
        // assertion is about.
        $header = JwtParser::parse((string) self::anEvent())->header;

        self::assertSame('secevent+jwt', $header->type());
        self::assertSame('stream-2026', $header->keyId());
    }

    #[TestDox('an ID token is not a security event either')]
    public function testAnIdTokenIsRefused(): void
    {
        // Parity with the access-token row: the other profile this bundle can
        // mint, refused on the same `typ` check rather than on anything about
        // its claims.
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $idToken = IdTokenProfile::issuer(
            self::ISSUER,
            new Rs256(),
            RsaPrivateKey::fromPem(self::keypair('stream')['private'], 'RS256', 'stream-2026'),
        )->issue()
            ->subject('user-42')
            ->audience(self::RECEIVER)
            ->expiresIn(new DateInterval('PT5M'))
            ->build();

        $this->expectException(JwtException::class);

        self::receiver()->verify((string) $idToken);
    }

    #[TestDox('the configured leeway is the tolerance the receiver actually applies')]
    public function testLeewayReachesTheConsumer(): void
    {
        // A SET has no `exp`, so leeway here only ever forgives a transmitter
        // whose clock runs ahead. Asserted in both directions, because a
        // `DateInterval` that never reached the profile would leave the option
        // in the tree doing nothing and the reference documenting a lie.
        self::bootKernel(['medzuch_jwt' => self::configuration(leeway: 120)]);

        $ahead = self::transmitter()->issue()
            ->issuedAt(new \DateTimeImmutable('+60 seconds'))
            ->event(self::ACCOUNT_DISABLED)
            ->build();

        self::assertSame(self::ISSUER, self::receiver()->verify((string) $ahead)->getString('iss'));

        self::ensureKernelShutdown();
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        $stillAhead = self::transmitter()->issue()
            ->issuedAt(new \DateTimeImmutable('+60 seconds'))
            ->event(self::ACCOUNT_DISABLED)
            ->build();

        $this->expectException(JwtException::class);

        self::receiver()->verify((string) $stillAhead);
    }

    #[TestDox('a receiver whose audience is blank fails at container build')]
    public function testBlankAudienceIsRefused(): void
    {
        // Null is "accept whatever the token names"; a blank string reaches the
        // library as an expected `aud` of "", which no SET carries — so the
        // receiver would look configured and refuse every delivery.
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/Security event consumer "risc" has a blank audience/');

        self::bootKernel(['medzuch_jwt' => self::configuration(receiverAudience: '  ')]);
    }

    #[TestDox('a receiver can take its keys from a remote JWK Set')]
    public function testReceiverVerifiesAgainstARemoteSet(): void
    {
        // The wiring is shared with ID tokens, but this is a new call site of
        // it: a registrar that built the local set and forgot the resolver
        // would pass every other row here, since they all configure `keys`.
        self::bootKernel(['medzuch_jwt' => self::configuration(verifiesWith: [], remoteSet: 'idp')]);

        self::assertTrue(self::getContainer()->has('medzuch_jwt.security_event_consumer.risc'));
        self::assertInstanceOf(SecurityEventVerifier::class, self::getContainer()->get('medzuch_jwt.security_event_consumer.risc'));
    }

    #[TestDox('a stream signing with a key that has only a public half fails at container build')]
    public function testStreamNeedsAPrivateKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/Security event stream "risc" signs with key "public_only", which has only a public half/');

        self::bootKernel(['medzuch_jwt' => self::configuration(signsWith: 'public_only', publicOnlyKey: true)]);
    }

    #[TestDox('a stream naming a key that does not exist fails at container build')]
    public function testStreamNeedsAKnownKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/Security event stream "risc" signs with key "typo", which is not defined/');

        self::bootKernel(['medzuch_jwt' => self::configuration(signsWith: 'typo')]);
    }

    #[TestDox('a receiver with nothing to verify with fails at container build')]
    public function testReceiverNeedsKeys(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/Security event consumer "risc" has nothing to verify with/');

        self::bootKernel(['medzuch_jwt' => self::configuration(verifiesWith: [])]);
    }

    #[TestDox('both services are injectable by the name they were configured under')]
    public function testNamedAutowiring(): void
    {
        // The alias is what lets a controller ask for `SecurityEventVerifier
        // $risc` instead of pulling a string out of the container, and it is
        // registered per name rather than by type because a second stream would
        // otherwise be unreachable.
        self::bootKernel(['medzuch_jwt' => self::configuration()]);

        self::assertTrue(self::getContainer()->has(SecurityEventIssuer::class . ' $risc'));
        self::assertTrue(self::getContainer()->has(SecurityEventVerifier::class . ' $risc'));
    }

    /** @return array<string, mixed> */
    private static function events(ClaimsSet $claims): array
    {
        $events = $claims->get('events');
        self::assertIsArray($events);

        /** @var array<string, mixed> $events */
        return $events;
    }

    private static function anEvent(): \Medzuch\Jwt\Jws\CompactJws
    {
        return self::transmitter()->issue()->event(self::ACCOUNT_DISABLED)->build();
    }

    private static function transmitter(): SecurityEventIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.security_event_issuer.risc');
        self::assertInstanceOf(SecurityEventIssuer::class, $issuer);

        return $issuer;
    }

    private static function receiver(): SecurityEventVerifier
    {
        $verifier = self::getContainer()->get('medzuch_jwt.security_event_consumer.risc');
        self::assertInstanceOf(SecurityEventVerifier::class, $verifier);

        return $verifier;
    }

    /**
     * One keypair, both halves configured: the transmitter signs with the
     * private one and the receiver verifies with the public one, which is the
     * two-application setup collapsed into a single kernel.
     *
     * Everything a row varies is a parameter rather than something it reaches
     * into the returned array to change: the array is `array<string, mixed>`,
     * so a nested write is a write through `mixed` and static analysis is right
     * to refuse it.
     *
     * @param list<string> $verifiesWith names the receiver verifies with
     * @param bool         $addressed    whether the stream names an audience and the
     *                                   receiver requires one; false is the single-subscriber setup
     *
     * @return array<string, mixed>
     */
    private static function configuration(
        string $issuer = self::ISSUER,
        string $signsWith = 'stream',
        array $verifiesWith = ['stream'],
        bool $addressed = true,
        bool $publicOnlyKey = false,
        int $leeway = 0,
        ?string $receiverAudience = null,
        ?string $remoteSet = null,
    ): array {
        $keys = [
            'stream' => [
                'pem_private' => self::keypair('stream')['private'],
                'pem_public' => self::keypair('stream')['public'],
                'algorithm' => 'RS256',
                'kid' => 'stream-2026',
            ],
        ];

        if ($publicOnlyKey) {
            $keys['public_only'] = ['pem_public' => self::keypair('stream')['public'], 'algorithm' => 'RS256'];
        }

        return [
            'keys' => $keys,
            'remote_jwks' => null === $remoteSet ? [] : [$remoteSet => [
                'uri' => 'https://idp.test/.well-known/jwks.json',
                'http_client' => 'test.http_client',
                'cache' => 'test.cache',
            ]],
            'security_events' => [
                'issuers' => [
                    'risc' => [
                        'issuer' => self::ISSUER,
                        'key' => $signsWith,
                    ] + ($addressed ? ['audience' => self::RECEIVER] : []),
                ],
                'consumers' => [
                    'risc' => [
                        'issuer' => $issuer,
                        'keys' => $verifiesWith,
                        'allowed_algorithms' => ['RS256'],
                        'remote_jwks' => $remoteSet,
                        'audience' => $receiverAudience ?? ($addressed ? self::RECEIVER : null),
                        'leeway' => $leeway,
                    ],
                ],
            ],
        ];
    }
}
