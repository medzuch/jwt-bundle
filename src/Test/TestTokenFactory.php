<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Test;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use Medzuch\Jwt\Algorithm\Signing\Hs256;
use Medzuch\Jwt\Algorithm\Signing\Hs384;
use Medzuch\Jwt\Algorithm\Signing\Hs512;
use Medzuch\Jwt\Algorithm\SigningAlgorithm;
use Medzuch\Jwt\Key\HmacKey;
use Medzuch\Jwt\Key\PrivateKey;
use Medzuch\Jwt\Primitives\FrozenClock;
use Medzuch\Jwt\Profile\AccessTokenBuilder;
use Medzuch\Jwt\Profile\AccessTokenProfile;
use Psr\Clock\ClockInterface;

/**
 * Mints the tokens a functional test needs, including the ones an issuer will
 * not make: expired, not yet valid, addressed elsewhere, signed by a stranger.
 *
 * README "Testing an application that uses this" has the recipes and the reason
 * it reads no configuration.
 *
 * Ships in `src/` rather than in this package's own test suite because it is
 * for applications using the bundle. It calls no assertion library and needs
 * none.
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
        return $this->copy(clientId: $clientId);
    }

    /**
     * Lifetime of the tokens {@see self::token()} mints. The two refusals below
     * have their own hour-wide offsets, far enough outside any sane `leeway`
     * that a consumer configured with one still refuses them.
     */
    public function withTtl(int $seconds): self
    {
        if ($seconds < 1) {
            // The same refusal `AccessTokenIssuer` makes, and for the same
            // reason: a token alive for no time is not a shorter token, and
            // `sprintf('PT%dS', -60)` is a malformed interval rather than a
            // message anyone can act on. A token that has already expired is
            // what expired() is for.
            throw new InvalidArgumentException(sprintf('A lifetime is a whole number of seconds, greater than zero; got %d. For a token that is already past its expiry, use expired().', $seconds));
        }

        return $this->copy(ttl: $seconds);
    }

    /**
     * The clock the token is dated by, which is the consumer's own in a test
     * that froze it: `iat` from one clock and `exp` checked against another is
     * a token that expires at a time nobody agreed on.
     */
    public function withClock(ClockInterface $clock): self
    {
        return $this->copy(clock: $clock);
    }

    /** A token from somewhere this consumer does not trust. */
    public function withIssuer(string $issuer): self
    {
        return $this->copy(issuer: $issuer);
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
        return $this->copy(audience: self::listOf($audience));
    }

    /**
     * The one place the seven constructor arguments are listed positionally.
     * Six `with…()` methods each re-listing them is six chances to transpose
     * two, and a suite that only ever mints valid tokens would not notice.
     *
     * @param non-empty-list<string>|null $audience
     */
    private function copy(
        ?string $issuer = null,
        ?array $audience = null,
        ?string $clientId = null,
        ?int $ttl = null,
        ?ClockInterface $clock = null,
    ): self {
        return new self(
            $issuer ?? $this->issuer,
            $audience ?? $this->audience,
            $this->algorithm,
            $this->key,
            $clientId ?? $this->clientId,
            $ttl ?? $this->ttl,
            $clock ?? $this->clock,
        );
    }

    /**
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims claims of the application's own. The registered
     *                                     ones are set from the arguments above and from
     *                                     `with…()`; the library refuses them here
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
        // Dated by a clock two hours back, so `iat` precedes `exp` the way it
        // does on a token that really did go stale. Minted at "now" the token
        // would carry an `exp` an hour before its own `iat`, which is refused
        // for being expired and is also nonsense — and nonsense is what a
        // later check, or `jwt:token:inspect`, would report instead of the
        // reason this method's name promises.
        $issued = new FrozenClock($this->now()->modify('-2 hours'));

        return (string) $this->build($subject, $scopes, $claims, $jti, $issued)
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
    private function build(string $subject, array $scopes, array $claims, ?string $jti, ?ClockInterface $clock = null): AccessTokenBuilder
    {
        $profile = AccessTokenProfile::issuer($this->issuer, $this->algorithm, $this->key, $clock ?? $this->clock);

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
        $audience = is_string($audience) ? [$audience] : $audience;

        if ([] === $audience) {
            // The phpdoc says non-empty and nothing enforced it. An empty `aud`
            // mints a token refused for a reason no test named, which is the
            // worst kind of green-to-red.
            throw new InvalidArgumentException('A token is addressed to somebody: give at least one audience.');
        }

        return $audience;
    }
}
