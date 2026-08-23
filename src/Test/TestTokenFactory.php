<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Test;

use DateInterval;
use DateTimeImmutable;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs384;
use Medzuch\Jwt\Algorithm\Signing\Hs512;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Profile\AccessTokenBuilder;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Psr\Clock\ClockInterface;

/**
 * Mints the tokens a functional test needs, including the ones an issuer will
 * not make.
 *
 * `AccessTokenIssuer` mints tokens meant to work: it takes the configured key,
 * audience and lifetime, and refuses a negative TTL. Testing a firewall needs
 * the other half — a token that expired an hour ago, one addressed to another
 * service, one from an issuer nobody trusts — and building those by hand is a
 * dozen lines of library calls repeated in every test case that needs one.
 *
 * **It reads no configuration, deliberately.** A test that mints from the same
 * container it verifies against cannot catch a configuration mistake: an
 * `audience` that is wrong in both halves agrees with itself, and the test
 * passes. Naming the issuer, the audience and the key here is what makes the
 * test an assertion about the contract rather than about the configuration's
 * agreement with itself.
 *
 * A token nobody should accept is a factory of its own — nothing to switch on:
 *
 *     $stranger = TestTokenFactory::hmac(self::ISSUER, self::AUDIENCE, 'another-secret-of-32-bytes-plus!!');
 *
 * Ships in `src/`, not in the test suite, because it is for applications using
 * this bundle. It calls no assertion library and needs none.
 */
final class TestTokenFactory
{
    /** @var non-empty-list<string> */
    private readonly array $audience;

    /**
     * @param non-empty-list<string> $audience
     */
    private function __construct(
        private readonly string $issuer,
        array $audience,
        private readonly SigningAlgorithm $algorithm,
        private readonly PrivateKey $key,
        private readonly string $clientId = 'test-client',
        private readonly int $ttl = 300,
        private readonly ?ClockInterface $clock = null,
    ) {
        $this->audience = $audience;
    }

    /**
     * @param string|non-empty-list<string> $audience
     * @param 'HS256'|'HS384'|'HS512'       $algorithm
     * @param string|null                   $kid       the key id the token's header names, for a consumer that resolves by one
     */
    public static function hmac(string $issuer, string|array $audience, string $secret, string $algorithm = 'HS256', ?string $kid = null): self
    {
        $signer = match ($algorithm) {
            'HS384' => new Hs384(),
            'HS512' => new Hs512(),
            default => new Hs256(),
        };

        // The `kid` belongs to the key rather than to the token, which is why
        // it is here and not on a `with…()`: a consumer that resolves by `kid`
        // is answering a question about which key signed, and a test naming one
        // the consumer has not got is testing exactly that.
        return new self($issuer, self::listOf($audience), $signer, HmacKey::fromBinary($secret, $algorithm, $kid));
    }

    /**
     * The asymmetric half: an application testing an RS256 or EdDSA firewall
     * holds the private key its issuer signs with, and this takes it as it is
     * rather than re-deriving it from a PEM path the bundle already read.
     *
     * @param string|non-empty-list<string> $audience
     */
    public static function signedWith(string $issuer, string|array $audience, SigningAlgorithm $algorithm, PrivateKey $key): self
    {
        return new self($issuer, self::listOf($audience), $algorithm, $key);
    }

    public function withClientId(string $clientId): self
    {
        return new self($this->issuer, $this->audience, $this->algorithm, $this->key, $clientId, $this->ttl, $this->clock);
    }

    /**
     * Lifetime of the tokens {@see self::token()} mints. The two refusals below
     * have their own hour-wide offsets, far enough outside any sane `leeway`
     * that a consumer configured with one still refuses them.
     */
    public function withTtl(int $seconds): self
    {
        return new self($this->issuer, $this->audience, $this->algorithm, $this->key, $this->clientId, $seconds, $this->clock);
    }

    /**
     * The clock the token is dated by, which is the consumer's own in a test
     * that froze it: `iat` from one clock and `exp` checked against another is
     * a token that expires at a time nobody agreed on.
     */
    public function withClock(ClockInterface $clock): self
    {
        return new self($this->issuer, $this->audience, $this->algorithm, $this->key, $this->clientId, $this->ttl, $clock);
    }

    /** A token from somewhere this consumer does not trust. */
    public function withIssuer(string $issuer): self
    {
        return new self($issuer, $this->audience, $this->algorithm, $this->key, $this->clientId, $this->ttl, $this->clock);
    }

    /**
     * A token addressed elsewhere — or, with a list, to this consumer among
     * others, which an `exclusive` audience policy refuses and the default one
     * accepts.
     *
     * @param string|non-empty-list<string> $audience
     */
    public function withAudience(string|array $audience): self
    {
        return new self($this->issuer, self::listOf($audience), $this->algorithm, $this->key, $this->clientId, $this->ttl, $this->clock);
    }

    /**
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims
     */
    public function token(string $subject = 'test-user', array $scopes = [], array $claims = [], ?string $jti = null): string
    {
        return (string) $this->build($subject, $scopes, $claims, $jti)
            ->expiresIn(new DateInterval(sprintf('PT%dS', $this->ttl)))
            ->build();
    }

    /**
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims
     */
    public function expired(string $subject = 'test-user', array $scopes = [], array $claims = [], ?string $jti = null): string
    {
        return (string) $this->build($subject, $scopes, $claims, $jti)
            ->expiresAt($this->now()->modify('-1 hour'))
            ->build();
    }

    /**
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims
     */
    public function notYetValid(string $subject = 'test-user', array $scopes = [], array $claims = [], ?string $jti = null): string
    {
        return (string) $this->build($subject, $scopes, $claims, $jti)
            ->notBefore($this->now()->modify('+1 hour'))
            ->expiresIn(new DateInterval('PT2H'))
            ->build();
    }

    /**
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims
     */
    private function build(string $subject, array $scopes, array $claims, ?string $jti): AccessTokenBuilder
    {
        $profile = AccessTokenProfile::issuer($this->issuer, $this->algorithm, $this->key, $this->clock);

        $builder = $profile->issue()
            ->subject($subject)
            ->audience($this->audience)
            ->clientId($this->clientId)
            // Named even when the caller did not ask: RFC 9068 §2.2 requires
            // `jti`, and a token this factory mints should be one the profile
            // it was minted with would accept.
            ->jwtId($jti ?? bin2hex(random_bytes(16)));

        if ([] !== $scopes) {
            $builder = $builder->scope($scopes);
        }

        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder;
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock?->now() ?? new DateTimeImmutable();
    }

    /**
     * @param string|non-empty-list<string> $audience
     *
     * @return non-empty-list<string>
     */
    private static function listOf(string|array $audience): array
    {
        return is_string($audience) ? [$audience] : $audience;
    }
}
