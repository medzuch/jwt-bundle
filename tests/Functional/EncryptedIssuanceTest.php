<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\JwtBuilder;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\KeyUse;
use Medzuch\Jwt\Key\OctKey;
use Medzuch\Jwt\Primitives\Base64Url;
use Medzuch\Jwt\Primitives\Json;
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Medzuch\JwtBundle\Issuer\TokenEnvelope;
use Medzuch\JwtBundle\Security\AccessTokenHandler;
use Medzuch\JwtBundle\Security\RejectedTokenException;
use Medzuch\JwtBundle\Security\RejectionReason;
use Medzuch\JwtBundle\Tests\Functional\App\RecordsVerification;
use Medzuch\JwtBundle\Tests\Functional\App\SecuredKernel;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Minting an encrypted token: sign, then encrypt (I8), which is the half C12
 * left to somebody else's code.
 *
 * The pair is what these cases are about. An issuer with a `jwe` block and a
 * consumer with one are two halves of the same envelope, and the tokens that
 * cross between them here are minted by this bundle rather than assembled with
 * the library — which is the only way to find out whether the two halves agree
 * about `kid`, about `cty`, and about the shape of a replicated claim.
 *
 * Everything above the envelope is asserted to be unchanged: the claims, the
 * `jti` the caller may later revoke on, and the lifetime reported back belong
 * to the token inside, because encryption is what it travels in rather than
 * part of what it says.
 */
#[CoversClass(TokenEnvelope::class)]
#[CoversClass(AccessTokenIssuer::class)]
final class EncryptedIssuanceTest extends WebTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';
    private const ISSUER = 'https://issuer.test';
    private const AUDIENCE = 'https://api.test';

    /** Exactly 32 bytes: what A256KW is made of, and what a `dir` key for A256GCM has to be. */
    private const SEALING = '0123456789abcdef0123456789abcdef';

    private const KID = 'enc-2026';

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? self::configuration();
        $config = is_array($config) ? $config : [];

        return ($options['firewall'] ?? false) === true ? new SecuredKernel($config) : new TestKernel($config);
    }

    #[TestDox('a token this application seals authenticates through this application\'s own firewall')]
    public function testTheTwoHalvesMeet(): void
    {
        $client = self::createClient(['firewall' => true]);

        $token = self::issuer()->issue('alice');

        $client->request('GET', '/api/whoami', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->value]);

        self::assertResponseIsSuccessful();
        self::assertSame(['user' => 'alice', 'roles' => ['ROLE_USER']], self::json($client));
    }

    #[TestDox('what the issuer hands back is a JWE, and its outer header says so')]
    public function testWhatIsHandedBackIsSealed(): void
    {
        self::bootKernel();

        $token = self::issuer()->issue('alice')->value;

        self::assertCount(5, explode('.', $token), 'a JWE has five segments where a signed token has three');

        // Canonicalizing: a JSON object has no order, and which member the
        // library writes first is not what this case is about. That every
        // member is there and no other is, is.
        self::assertEqualsCanonicalizing(
            ['kid' => self::KID, 'cty' => 'JWT', 'alg' => 'A256KW', 'enc' => 'A256GCM'],
            self::outerHeader($token),
        );
    }

    /**
     * The claim the pair rests on: the envelope is a wrapper and nothing that
     * was decided above it moved. The `jti` matters most — it is what an
     * application records to revoke this token later, and it names the token
     * inside, which is the one a consumer will judge.
     */
    #[TestDox('the claims, the lifetime and the jti are the token\'s own')]
    public function testNothingAboveTheEnvelopeChanged(): void
    {
        self::bootKernel();

        $token = self::issuer()->issue('alice', ['read'], ['tenant' => 'acme'], ttl: 60);

        self::assertSame('alice', self::handler()->getUserBadgeFrom($token->value)->getUserIdentifier());

        $claims = self::accepted()->all();

        self::assertSame(60, $token->expiresIn);
        self::assertSame($token->jti, $claims['jti'] ?? null);
        self::assertSame('alice', $claims['sub'] ?? null);
        self::assertSame('read', $claims['scope'] ?? null);
        self::assertSame('acme', $claims['tenant'] ?? null);
    }

    /**
     * Proof that the encryption is real rather than a shape: the same token
     * offered to a consumer holding every signing key it needs, and no `jwe`
     * block, gets nowhere.
     */
    #[TestDox('a consumer that does not decrypt cannot read it')]
    public function testAConsumerWithoutTheBlockIsStuck(): void
    {
        self::bootKernel();

        self::assertSame(RejectionReason::Malformed, self::refusal(self::issuer()->issue('alice')->value, 'plain'));
    }

    #[TestDox('"dir" seals with the configured key itself')]
    public function testDirectEncryption(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(
            jweKeys: ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256GCM', 'kid' => self::KID]],
            issuerJwe: ['key' => 'sealed', 'key_management' => 'dir', 'content_encryption' => 'A256GCM'],
            consumerJwe: ['keys' => ['sealed'], 'allowed_key_management' => ['dir'], 'allowed_content_encryption' => ['A256GCM']],
        )]);

        $token = self::issuer()->issue('alice')->value;

        self::assertEqualsCanonicalizing(['kid' => self::KID, 'cty' => 'JWT', 'alg' => 'dir', 'enc' => 'A256GCM'], self::outerHeader($token));
        self::assertSame('alice', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * RFC 7519 §5.3, from the sending side. The point of replicating `iss` is
     * an intermediary that routes on it without holding a key, so the value has
     * to be readable in the outer header — and it has to be the claim, because
     * the receiver compares the two and must reject a token where they differ.
     */
    #[TestDox('a replicated claim is in the outer header and equals the claim inside')]
    public function testReplicatedClaims(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(replicated: ['iss', 'aud'])]);

        $token = self::issuer()->issue('alice')->value;
        $header = self::outerHeader($token);

        self::assertSame(self::ISSUER, $header['iss'] ?? null);

        // The shape as well as the value. The bundle always mints `aud` as a
        // list, and an outer `"https://api.test"` beside an inner
        // `["https://api.test"]` is a disagreement the receiver refuses.
        self::assertSame([self::AUDIENCE], $header['aud'] ?? null);

        // And the consumer, which is the half that enforces §5.3, agrees —
        // then the claims it accepted are compared to the header this test
        // read for itself, which is the equality §5.3 is about.
        self::assertSame('alice', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());

        $claims = self::accepted();
        self::assertSame($header['iss'] ?? null, $claims->issuer());
        self::assertSame($header['aud'] ?? null, $claims->get('aud'));
    }

    #[TestDox('a claim the token does not carry is not written into the header')]
    public function testAnAbsentClaimIsNotReplicated(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(replicated: ['iss', 'scope'])]);

        // No scopes, so there is no `scope` claim. §5.3 is about a claim that
        // was repeated; a header member with no claim behind it would be an
        // unauthenticated value the receiver never compares to anything.
        $header = self::outerHeader(self::issuer()->issue('alice')->value);

        self::assertArrayNotHasKey('scope', $header);
        self::assertSame(self::ISSUER, $header['iss'] ?? null);

        self::assertSame('read', self::outerHeader(self::issuer()->issue('alice', ['read'])->value)['scope'] ?? null);
    }

    /**
     * The narrower of the two rotations. A receiver keeps a list and accepts
     * both keys; a sender names one, and the change here is that name.
     */
    #[TestDox('the sender names one key while the receiver still accepts two')]
    public function testRotatingTheSealingKey(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(
            jweKeys: [
                'old' => ['secret' => self::SEALING, 'algorithm' => 'A256KW', 'kid' => 'enc-2025'],
                'new' => ['secret' => strrev(self::SEALING), 'algorithm' => 'A256KW', 'kid' => self::KID],
            ],
            issuerJwe: ['key' => 'new', 'key_management' => 'A256KW', 'content_encryption' => 'A256GCM'],
            consumerJwe: ['keys' => ['old', 'new'], 'allowed_key_management' => ['A256KW'], 'allowed_content_encryption' => ['A256GCM']],
        )]);

        $token = self::issuer()->issue('alice')->value;

        self::assertSame(self::KID, self::outerHeader($token)['kid'] ?? null);
        self::assertSame('alice', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * A `kid` is not required of a wrapping key, and where there is none the
     * outer header carries none: the recipient falls back to the header's
     * `alg`, and a key bound to that is exactly what it finds. Only `dir` has
     * no such fallback, which is why a `dir` key is refused without one.
     */
    #[TestDox('a key with no kid seals a token whose outer header names none')]
    public function testAKeyWithoutAKid(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(
            jweKeys: ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256KW']],
        )]);

        $token = self::issuer()->issue('alice')->value;

        self::assertEqualsCanonicalizing(['cty' => 'JWT', 'alg' => 'A256KW', 'enc' => 'A256GCM'], self::outerHeader($token));
        self::assertSame('alice', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * A second family, because the first is the one everything else here is
     * written in: AES-GCM key wrapping, and a CBC-HS content algorithm whose
     * Content Encryption Key is twice the length of its own key. Nothing in
     * the bundle chooses differently between them — it is the same
     * `NestedJwtBuilder::wrap()` call — which is exactly why a second family
     * is worth minting through rather than reasoning about.
     */
    #[TestDox('another family of algorithms round-trips the same way')]
    public function testASecondAlgorithmFamily(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(
            // 16 bytes: what A128GCMKW is made of. The content key it wraps is
            // 48 bytes for A192CBC-HS384 and is minted fresh per token.
            jweKeys: ['sealed' => ['secret' => substr(self::SEALING, 0, 16), 'algorithm' => 'A128GCMKW', 'kid' => self::KID]],
            issuerJwe: ['key' => 'sealed', 'key_management' => 'A128GCMKW', 'content_encryption' => 'A192CBC-HS384'],
            consumerJwe: ['keys' => ['sealed'], 'allowed_key_management' => ['A128GCMKW'], 'allowed_content_encryption' => ['A192CBC-HS384']],
        )]);

        $token = self::issuer()->issue('alice')->value;
        $header = self::outerHeader($token);

        self::assertSame('A128GCMKW', $header['alg'] ?? null);
        self::assertSame('A192CBC-HS384', $header['enc'] ?? null);
        // AES-GCM key wrapping contributes its own `iv` and `tag` to the
        // protected header, which is the library's business and not this
        // bundle's — asserted only so the case notices if they stop arriving.
        self::assertArrayHasKey('iv', $header);
        self::assertArrayHasKey('tag', $header);

        self::assertSame('alice', self::handler()->getUserBadgeFrom($token)->getUserIdentifier());
    }

    /**
     * The configuration refuses a replicated claim named after a JOSE header
     * parameter, so this cannot arrive through a container. Asserted on the
     * object anyway: the invariant is the envelope's, and a `kid` naming a key
     * the recipient does not have would be a token nobody could open, minted
     * on purpose.
     */
    #[TestDox('a replicated claim cannot take the place of the key\'s kid')]
    public function testTheKeyIdIsNotOverwritable(): void
    {
        self::bootKernel();

        $envelope = new TokenEnvelope(
            new A256Kw(),
            new A256Gcm(),
            OctKey::fromBinary(self::SEALING, 'A256KW', self::KID, KeyUse::Enc),
            ['kid'],
        );

        $signed = JwtBuilder::create()
            ->issuer(self::ISSUER)
            ->subject('alice')
            ->withClaim('kid', 'not-a-key-id')
            ->signWith(new Hs256(), HmacKey::fromBinary(self::SECRET, 'HS256'))
            ->build();

        self::assertSame(self::KID, self::outerHeader($envelope->seal($signed))['kid'] ?? null);
    }

    #[TestDox('an issuer without the block still mints a signed token')]
    public function testAnIssuerWithoutTheBlockIsUnchanged(): void
    {
        self::bootKernel(['medzuch_jwt' => self::configuration(issuerJwe: false)]);

        self::assertCount(3, explode('.', self::issuer()->issue('alice')->value));
    }

    /**
     * @return array<string, mixed>
     */
    private static function outerHeader(string $token): array
    {
        $decoded = Json::decode(Base64Url::decode(explode('.', $token)[0]));
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * The claims of the last token a consumer accepted.
     */
    private static function accepted(): ClaimsSet
    {
        $listener = self::getContainer()->get('test.verification_listener');
        self::assertInstanceOf(RecordsVerification::class, $listener);
        self::assertNotSame([], $listener->verified);

        return $listener->verified[array_key_last($listener->verified)]->claims;
    }

    private static function refusal(string $token, string $consumer): RejectionReason
    {
        try {
            self::handler($consumer)->getUserBadgeFrom($token);
        } catch (RejectedTokenException $failure) {
            return $failure->reason;
        }

        self::fail('the token should have been refused');
    }

    private static function issuer(string $name = 'default'): AccessTokenIssuer
    {
        $issuer = self::getContainer()->get('medzuch_jwt.issuer.' . $name);
        self::assertInstanceOf(AccessTokenIssuer::class, $issuer);

        return $issuer;
    }

    private static function handler(string $name = 'api'): AccessTokenHandler
    {
        $handler = self::getContainer()->get('medzuch_jwt.handler.' . $name);
        self::assertInstanceOf(AccessTokenHandler::class, $handler);

        return $handler;
    }

    /**
     * @return array<string, mixed>
     */
    private static function json(KernelBrowser $client): array
    {
        $decoded = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param array<string, mixed>|null       $jweKeys
     * @param array<string, mixed>|false|null $issuerJwe  false leaves the issuer unsealed
     * @param array<string, mixed>|null       $consumerJwe
     * @param list<string>                    $replicated
     *
     * @return array<string, mixed>
     */
    private static function configuration(?array $jweKeys = null, array|false|null $issuerJwe = null, ?array $consumerJwe = null, array $replicated = []): array
    {
        $jwe = false === $issuerJwe ? [] : ['jwe' => ($issuerJwe ?? [
            'key' => 'sealed',
            'key_management' => 'A256KW',
            'content_encryption' => 'A256GCM',
        ]) + ([] === $replicated ? [] : ['replicated_claims' => $replicated])];

        return [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'jwe_keys' => $jweKeys ?? ['sealed' => ['secret' => self::SEALING, 'algorithm' => 'A256KW', 'kid' => self::KID]],
            'issuers' => [
                'default' => $jwe + [
                    'issuer' => self::ISSUER,
                    'key' => 'default',
                    'client_id' => 'test-client',
                    'audience' => self::AUDIENCE,
                ],
            ],
            'consumers' => [
                'api' => [
                    'issuer' => self::ISSUER,
                    'audience' => self::AUDIENCE,
                    'keys' => ['default'],
                    'allowed_algorithms' => ['HS256'],
                    'jwe' => $consumerJwe ?? [
                        'keys' => ['sealed'],
                        'allowed_key_management' => ['A256KW'],
                        'allowed_content_encryption' => ['A256GCM'],
                    ],
                ],
                'plain' => [
                    'issuer' => self::ISSUER,
                    'audience' => self::AUDIENCE,
                    'keys' => ['default'],
                    'allowed_algorithms' => ['HS256'],
                ],
            ],
        ];
    }
}
