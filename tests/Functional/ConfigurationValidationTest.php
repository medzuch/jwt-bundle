<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional;

use Medzuch\JwtBundle\MedzuchJwtBundle;
use Medzuch\JwtBundle\Tests\Functional\App\TestKernel;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * Every case here is a wiring mistake that would otherwise surface as a token
 * being rejected at runtime — with a message about the token, not about the
 * configuration that can never accept one.
 */
#[CoversClass(MedzuchJwtBundle::class)]
final class ConfigurationValidationTest extends KernelTestCase
{
    use RestoresExceptionHandler;

    private const SECRET = 'a-shared-secret-of-at-least-32-bytes!';

    /** Exactly 32 bytes, which A256KW and a `dir` key for A256GCM both are. */
    private const JWE_SECRET = '0123456789abcdef0123456789abcdef';

    /** Never parsed: every case below is refused before any key is built. */
    private const PEM = "-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----";

    /**
     * @param array<array-key, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        $config = $options['medzuch_jwt'] ?? [];

        return new TestKernel(is_array($config) ? $config : []);
    }

    #[TestDox('a consumer naming a key that does not exist fails at container build')]
    public function testUnknownKeyReference(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/names key "typo"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['keys' => ['typo']])],
        ]]);
    }

    #[TestDox('an allowed algorithm with no key behind it fails at container build')]
    public function testConsumerThatCanNeverVerify(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/could never be verified/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET, 'algorithm' => 'HS256']],
            'consumers' => ['api' => self::consumer(['allowed_algorithms' => ['RS256']])],
        ]]);
    }

    #[TestDox('two kid-less keys on one algorithm fail at container build (DEC-5)')]
    public function testIndistinguishableKeys(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/cannot say which one signed it/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['hmac' => self::SECRET],
                'previous' => ['hmac' => self::SECRET . '-old'],
            ],
            'consumers' => ['api' => self::consumer(['keys' => ['current', 'previous']])],
        ]]);
    }

    #[TestDox('the same two keys are fine once each carries a kid')]
    public function testDistinguishableKeysAreAccepted(): void
    {
        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['hmac' => self::SECRET, 'kid' => '2026-01'],
                'previous' => ['hmac' => self::SECRET . '-old', 'kid' => '2025-07'],
            ],
            'consumers' => ['api' => self::consumer(['keys' => ['current', 'previous']])],
        ]]);

        self::assertTrue(self::getContainer()->has('medzuch_jwt.handler.api'));
    }

    #[TestDox('an algorithm on the allowlist with no key is refused even when another one is satisfied')]
    public function testPartiallySatisfiedAllowlist(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/allows RS256/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['allowed_algorithms' => ['HS256', 'RS256']])],
        ]]);
    }

    #[TestDox('two keys sharing a kid fail at container build')]
    public function testDuplicateKid(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/share the kid "2026-01"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['hmac' => self::SECRET, 'kid' => '2026-01'],
                'previous' => ['hmac' => self::SECRET . '-old', 'kid' => '2026-01'],
            ],
            'consumers' => ['api' => self::consumer(['keys' => ['current', 'previous']])],
        ]]);
    }

    #[TestDox('an empty kid is refused at container build rather than when the key is first used')]
    public function testEmptyKid(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET, 'kid' => '']],
            'consumers' => ['api' => self::consumer()],
        ]]);
    }

    #[TestDox('a map where a sequence is expected names the configuration key, not the token')]
    public function testAudienceAsMap(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/must be a sequence, not a map/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['audience' => ['primary' => 'https://api.test']])],
        ]]);
    }

    #[TestDox('leeway above the library ceiling fails at container build')]
    public function testLeewayCeiling(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['leeway' => 3600])],
        ]]);
    }

    #[TestDox('a max token age of zero fails at container build, rather than meaning "off"')]
    public function testMaxTokenAgeFloor(): void
    {
        // Off is the key left out. Zero would read as "accept nothing", which
        // is a consumer that refuses every token it verifies — a configuration
        // nobody means, and one that would look like a token problem at
        // runtime rather than a configuration one at build.
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['max_token_age' => 0])],
        ]]);
    }

    #[TestDox('an unknown algorithm name fails at container build')]
    public function testUnknownAlgorithm(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['allowed_algorithms' => ['none']])],
        ]]);
    }

    #[TestDox('an issuer signing with a key that does not exist fails at container build')]
    public function testIssuerWithUnknownKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/signs with key "typo"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['key' => 'typo'])],
        ]]);
    }

    #[TestDox('a static claim using a registered claim name fails at container build, not at the first token')]
    public function testStaticClaimOverRegisteredName(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/registered claims/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['claims' => ['sub' => 'service-account']])],
        ]]);
    }

    #[TestDox('a static claim the library does not reserve is accepted')]
    public function testStaticClaimIsAccepted(): void
    {
        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['claims' => ['tenant' => 'acme']])],
        ]]);

        self::assertTrue(self::getContainer()->has('medzuch_jwt.issuer.default'));
    }

    #[TestDox('an issuer audience written as a map names the configuration key')]
    public function testIssuerAudienceAsMap(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/must be a sequence, not a map/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'issuers' => ['default' => self::issuer(['audience' => ['primary' => 'https://api.test']])],
        ]]);
    }

    #[TestDox('a key giving both a secret and a PEM fails at container build')]
    public function testKeyWithTwoKindsOfMaterial(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/A key is one thing/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET, 'pem_public' => self::PEM]],
        ]]);
    }

    #[TestDox('a key with no material at all fails at container build')]
    public function testKeyWithoutMaterial(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/has no material/');

        self::bootKernel(['medzuch_jwt' => ['keys' => ['default' => ['algorithm' => 'HS256']]]]);
    }

    #[TestDox('an HMAC algorithm given a PEM fails at container build')]
    public function testHmacAlgorithmWithPem(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/takes a shared secret, not a key pair/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['pem_public' => self::PEM, 'algorithm' => 'HS256']],
        ]]);
    }

    #[TestDox('an RSA algorithm given a shared secret fails at container build')]
    public function testRsaAlgorithmWithSecret(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/needs a key pair, not a shared secret/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET, 'algorithm' => 'RS256']],
        ]]);
    }

    #[TestDox('EdDSA given a PEM says which source it takes instead')]
    public function testEdDsaHasNoPemSource(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/is configured as a JWK/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['pem_public' => self::PEM, 'algorithm' => 'EdDSA']],
        ]]);
    }

    #[TestDox('a passphrase with nothing to unlock fails at container build')]
    public function testPassphraseWithoutPrivateKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/no "pem_private" to unlock/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['pem_public' => self::PEM, 'pem_passphrase' => 'x', 'algorithm' => 'RS256']],
        ]]);
    }

    #[TestDox('a consumer verifying with a private-only key fails at container build')]
    public function testConsumerWithPrivateOnlyKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/cannot stand in for it/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['pem_private' => self::PEM, 'algorithm' => 'RS256']],
            'consumers' => ['api' => self::consumer(['allowed_algorithms' => ['RS256']])],
        ]]);
    }

    #[TestDox('an issuer signing with a public-only key fails at container build')]
    public function testIssuerWithPublicOnlyKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/Signing needs the private half/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['pem_public' => self::PEM, 'algorithm' => 'RS256']],
            'issuers' => ['default' => self::issuer()],
        ]]);
    }

    #[TestDox('publishing a shared secret as JWKS fails at container build')]
    public function testJwksRefusesASharedSecret(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/gives away the key that signs/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'jwks' => ['keys' => ['default']],
        ]]);
    }

    #[TestDox('publishing a key with no public half fails at container build')]
    public function testJwksRefusesAPrivateOnlyKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/no public half to publish/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['pem_private' => self::PEM, 'algorithm' => 'RS256']],
            'jwks' => ['keys' => ['default']],
        ]]);
    }

    #[TestDox('publishing a key that does not exist fails at container build')]
    public function testJwksRefusesAnUnknownKey(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/publishes key "typo"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['pem_public' => self::PEM, 'algorithm' => 'RS256']],
            'jwks' => ['keys' => ['typo']],
        ]]);
    }

    #[TestDox('publishing the same key twice fails at container build')]
    public function testJwksRefusesADuplicateName(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/medzuch_jwt\.jwks names key "verify" more than once/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['verify' => ['pem_public' => self::PEM, 'algorithm' => 'RS256', 'kid' => '2026-01']],
            'jwks' => ['keys' => ['verify', 'verify']],
        ]]);
    }

    #[TestDox('publishing two keys that share a kid fails at container build (DEC-5)')]
    public function testJwksRefusesKeysSharingAKid(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        // The context matters as much as the message: the consumer check has
        // its own case, and one that named neither would pass with the jwks
        // call site deleted.
        $this->expectExceptionMessageMatches('/medzuch_jwt\.jwks uses keys .*share the kid "2026-01"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['pem_public' => self::PEM, 'algorithm' => 'RS256', 'kid' => '2026-01'],
                'previous' => ['pem_public' => self::PEM, 'algorithm' => 'RS256', 'kid' => '2026-01'],
            ],
            'jwks' => ['keys' => ['current', 'previous']],
        ]]);
    }

    #[TestDox('publishing two kid-less keys on one algorithm fails at container build (DEC-5)')]
    public function testJwksRefusesKidLessKeysOnOneAlgorithm(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/medzuch_jwt\.jwks uses keys .*with no "kid"/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => [
                'current' => ['pem_public' => self::PEM, 'algorithm' => 'RS256'],
                'previous' => ['pem_public' => self::PEM, 'algorithm' => 'RS256'],
            ],
            'jwks' => ['keys' => ['current', 'previous']],
        ]]);
    }

    #[TestDox('a consumer naming one key twice fails at container build')]
    public function testConsumerRefusesADuplicateName(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/Consumer "api" names key "default" more than once/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['keys' => ['default', 'default']])],
        ]]);
    }

    #[TestDox('no jwks section means no publisher, not an empty one')]
    public function testNoJwksMeansNoController(): void
    {
        self::bootKernel(['medzuch_jwt' => ['keys' => ['default' => ['hmac' => self::SECRET]]]]);

        self::assertFalse(self::getContainer()->has('medzuch_jwt.jwks_controller'));
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function issuer(array $overrides = []): array
    {
        return $overrides + [
            'issuer' => 'https://issuer.test',
            'key' => 'default',
            'client_id' => 'test-client',
            'audience' => 'https://api.test',
        ];
    }

    #[TestDox('a realm carrying a control character fails at container build')]
    public function testRealmWithAControlCharacter(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/quote, a backslash or a control character/');

        // The header would be dropped by PHP rather than emitted with a
        // newline in it, so the 401 this realm belongs to would go out saying
        // nothing about how to authenticate.
        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['realm' => "api\r\nX-Injected: yes"])],
        ]]);
    }

    #[TestDox('a realm carrying a quote still fails at container build')]
    public function testRealmWithAQuote(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/quote, a backslash or a control character/');

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'consumers' => ['api' => self::consumer(['realm' => 'api", error="insufficient_scope'])],
        ]]);
    }

    /**
     * @param array<string, mixed> $jwe
     * @param array<string, mixed> $jweKeys
     */
    #[DataProvider('unopenableConfigurations')]
    #[TestDox('$defect fails at container build')]
    public function testEncryptionThatCouldNeverOpenAToken(string $defect, array $jweKeys, array $jwe, string $expected): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches($expected);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'jwe_keys' => $jweKeys,
            'consumers' => ['api' => self::consumer(['jwe' => $jwe])],
        ]]);
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, array<string, mixed>, string}>
     */
    public static function unopenableConfigurations(): iterable
    {
        $wrapping = ['secret' => self::JWE_SECRET, 'algorithm' => 'A256KW', 'kid' => 'enc-1'];

        yield 'unknown key' => [
            'a consumer naming a JWE key that does not exist',
            ['sealed' => $wrapping],
            ['keys' => ['typo'], 'allowed_key_management' => ['A256KW'], 'allowed_content_encryption' => ['A256GCM']],
            '/decrypts with key "typo", which is not defined under medzuch_jwt.jwe_keys/',
        ];

        yield 'dir without a kid' => [
            'a key for "dir" with no kid, which no resolver could ever reach',
            ['sealed' => ['secret' => self::JWE_SECRET, 'algorithm' => 'A256GCM']],
            ['keys' => ['sealed'], 'allowed_key_management' => ['dir'], 'allowed_content_encryption' => ['A256GCM']],
            '/found by its "kid" and by nothing else/',
        ];

        yield 'algorithm with no key' => [
            'an allowed key-management algorithm no key can be used with',
            ['sealed' => $wrapping],
            ['keys' => ['sealed'], 'allowed_key_management' => ['A192KW'], 'allowed_content_encryption' => ['A256GCM']],
            '/allows A192KW .*could never be decrypted/',
        ];

        yield 'dir with no key for the content' => [
            'a consumer allowing "dir" whose only key is for a content algorithm it refuses',
            ['sealed' => ['secret' => self::JWE_SECRET, 'algorithm' => 'A256GCM', 'kid' => 'enc-1']],
            ['keys' => ['sealed'], 'allowed_key_management' => ['dir'], 'allowed_content_encryption' => ['A128GCM']],
            '/A "dir" key is bound to a content-encryption algorithm this consumer also allows \(A128GCM\)/',
        ];

        yield 'dir with an unbacked content algorithm' => [
            'a consumer decrypting only with "dir" and allowing a content algorithm no key is bound to',
            ['sealed' => ['secret' => self::JWE_SECRET, 'algorithm' => 'A256GCM', 'kid' => 'enc-1']],
            ['keys' => ['sealed'], 'allowed_key_management' => ['dir'], 'allowed_content_encryption' => ['A256GCM', 'A128GCM']],
            '/allows A128GCM for the content of a token it decrypts with "dir", and none of its JWE keys is bound to it/',
        ];

        yield 'key nothing allows' => [
            'a key bound to an algorithm the consumer does not allow',
            ['sealed' => $wrapping, 'spare' => ['secret' => substr(self::JWE_SECRET, 0, 24), 'algorithm' => 'A192KW', 'kid' => 'enc-2']],
            ['keys' => ['sealed', 'spare'], 'allowed_key_management' => ['A256KW'], 'allowed_content_encryption' => ['A256GCM']],
            '/names JWE key "spare", bound to A192KW, which nothing it allows can use/',
        ];

        yield 'indistinguishable' => [
            'two JWE keys on one algorithm with no kid between them',
            ['first' => ['secret' => self::JWE_SECRET, 'algorithm' => 'A256KW'], 'second' => ['secret' => strrev(self::JWE_SECRET), 'algorithm' => 'A256KW']],
            ['keys' => ['first', 'second'], 'allowed_key_management' => ['A256KW'], 'allowed_content_encryption' => ['A256GCM']],
            '/cannot say which one encrypted it/',
        ];

        yield 'shared kid' => [
            'two JWE keys sharing a kid, where selection reaches only the first',
            ['first' => $wrapping, 'second' => ['secret' => strrev(self::JWE_SECRET), 'algorithm' => 'A256KW', 'kid' => 'enc-1']],
            ['keys' => ['first', 'second'], 'allowed_key_management' => ['A256KW'], 'allowed_content_encryption' => ['A256GCM']],
            '/share the kid "enc-1"/',
        ];

        yield 'named twice' => [
            'one JWE key named twice, which puts it in the set twice',
            ['sealed' => $wrapping],
            ['keys' => ['sealed', 'sealed'], 'allowed_key_management' => ['A256KW'], 'allowed_content_encryption' => ['A256GCM']],
            '/names key "sealed" more than once/',
        ];
    }

    /**
     * @param array<string, mixed> $jwe
     * @param array<string, mixed> $jweKeys
     */
    #[DataProvider('unsealableConfigurations')]
    #[TestDox('$defect fails at container build')]
    public function testEncryptionThatCouldNeverSealAToken(string $defect, array $jweKeys, array $jwe, string $expected): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches($expected);

        self::bootKernel(['medzuch_jwt' => [
            'keys' => ['default' => ['hmac' => self::SECRET]],
            'jwe_keys' => $jweKeys,
            'issuers' => ['default' => self::issuer(['jwe' => $jwe])],
        ]]);
    }

    /**
     * The sending half of the same question (I8), and a shorter list: an issuer
     * names one key and one algorithm of each kind, so the only way to get it
     * wrong is to name a key that is not made of what the algorithm needs.
     *
     * @return iterable<string, array{string, array<string, mixed>, array<string, mixed>, string}>
     */
    public static function unsealableConfigurations(): iterable
    {
        $wrapping = ['secret' => self::JWE_SECRET, 'algorithm' => 'A256KW', 'kid' => 'enc-1'];

        yield 'unknown key' => [
            'an issuer naming a JWE key that does not exist',
            ['sealed' => $wrapping],
            ['key' => 'typo', 'key_management' => 'A256KW', 'content_encryption' => 'A256GCM'],
            '/encrypts with key "typo", which is not defined under medzuch_jwt.jwe_keys/',
        ];

        yield 'key for another algorithm' => [
            'an issuer wrapping with an algorithm its key is not bound to',
            ['sealed' => $wrapping],
            ['key' => 'sealed', 'key_management' => 'A192KW', 'content_encryption' => 'A256GCM'],
            '/encrypts with A192KW and JWE key "sealed", which is bound to A256KW.*name a key bound to A192KW/',
        ];

        yield 'dir key for another content algorithm' => [
            'an issuer encrypting directly with a key that is a key for something else',
            ['sealed' => ['secret' => self::JWE_SECRET, 'algorithm' => 'A256GCM', 'kid' => 'enc-1']],
            ['key' => 'sealed', 'key_management' => 'dir', 'content_encryption' => 'A128GCM'],
            '/encrypts with "dir" and A128GCM and JWE key "sealed", which is bound to A256GCM/',
        ];

        // The two crossed-purpose rows. Both messages have to offer a way out
        // the option would accept: a key-management name is not something
        // content can be encrypted with, and a content-encryption name is not
        // something a key can be wrapped with, so the advice changes sides.
        yield 'wrapping key used directly' => [
            'an issuer encrypting directly with a key that wraps',
            ['sealed' => $wrapping],
            ['key' => 'sealed', 'key_management' => 'dir', 'content_encryption' => 'A256GCM'],
            '/this one wraps keys instead — name a key bound to A256GCM, or wrap with it by setting key_management to A256KW/',
        ];

        yield 'content key used to wrap' => [
            'an issuer wrapping with a key that is a Content Encryption Key',
            ['sealed' => ['secret' => self::JWE_SECRET, 'algorithm' => 'A256GCM', 'kid' => 'enc-1']],
            ['key' => 'sealed', 'key_management' => 'A256KW', 'content_encryption' => 'A256GCM'],
            '/this one is a Content Encryption Key — name a key bound to A256KW, or use it directly with key_management "dir" and content_encryption A256GCM/',
        ];

        yield 'replicating a header parameter' => [
            'an issuer replicating a claim named after a JOSE header parameter',
            ['sealed' => $wrapping],
            ['key' => 'sealed', 'key_management' => 'A256KW', 'content_encryption' => 'A256GCM', 'replicated_claims' => ['iss', 'kid']],
            '/cannot be named after a registered JOSE header parameter/',
        ];
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function consumer(array $overrides = []): array
    {
        return $overrides + [
            'issuer' => 'https://issuer.test',
            'audience' => 'https://api.test',
            'keys' => ['default'],
            'allowed_algorithms' => ['HS256'],
        ];
    }
}
