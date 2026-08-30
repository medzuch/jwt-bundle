<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Verification;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Exception\InvalidHeaderException;
use Medzuch\Jwt\Jwe\CompactSerializer;
use Medzuch\Jwt\Jwe\Decrypter;
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\Jwt\Jwt\MediaType;
use Medzuch\Jwt\Key\KeyResolver;

/**
 * A consumer whose tokens arrive encrypted: a JWE wrapping the signed JWT
 * (RFC 7519 §5.2 nested JWT), which this opens before handing the inside to
 * the consumer that was already configured (C12).
 *
 * A decorator rather than a fourth kind of verifier, because encryption changes
 * what arrives and nothing about what is then checked. The issuer, audience,
 * algorithms, key set, leeway, profile and `typ` of the token inside are the
 * consumer's own, verified by the very object that would have verified an
 * unencrypted one — so a consumer does not acquire a second, quietly different
 * posture by being given a `jwe` block.
 *
 * **Stripping the encryption is not a way in.** A bare signed token presented
 * to a consumer configured this way has three segments where a JWE has five,
 * and is refused before a key is fetched. That is the whole reason the block
 * has no "optional" mode: an attacker who could drop the outer layer and still
 * be believed would have taken the confidentiality of the claims away for the
 * cost of two dots.
 *
 * Only the compact serialization is read. The JSON ones exist for recipients
 * and headers a bearer credential does not have, and a five-segment string is
 * what an `Authorization` header carries.
 *
 * **What the library's own {@see \Medzuch\Jwt\Jwt\NestedJwtParser} does and
 * this does not.** That class is the whole pipeline — decrypt, then parse and
 * verify the inner JWS against a signing allowlist of its own. Used here it
 * would verify the signature that the consumer behind this is about to verify
 * again, under a second copy of the same allowlist, and log both outcomes. So
 * the outer half is taken from {@see Decrypter}, which is the same code that
 * class calls, and the two rules it applies afterwards are restated below.
 *
 * @internal
 */
final class NestedTokenVerifier implements TokenVerifierInterface
{
    /**
     * JOSE header parameter names — RFC 7515 §4.1, RFC 7516 §4.1 and RFC 7797
     * §3 — which the RFC 7519 §5.3 check below skips.
     *
     * These are protocol metadata that drive routing and decryption, and they
     * share a namespace with claim names only by accident: an inner claim
     * called `kid` has nothing to do with the outer `kid` that said which key
     * to decrypt with, and comparing them would refuse a token for agreeing
     * with itself. Registered names are a fixed list in published RFCs rather
     * than a policy either side could change, which is what makes restating
     * them here safe.
     */
    private const JOSE_HEADER_PARAMETERS = [
        'alg', 'enc', 'zip',
        'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256',
        'typ', 'cty', 'crit',
        'epk', 'apu', 'apv', 'iv', 'tag', 'p2s', 'p2c',
        'b64',
    ];

    /**
     * @param non-empty-list<KeyManagementAlgorithm>     $allowedKeyManagement     accepted outer `alg`
     * @param non-empty-list<ContentEncryptionAlgorithm> $allowedContentEncryption accepted outer `enc`
     */
    public function __construct(
        private readonly TokenVerifierInterface $inner,
        private readonly Decrypter $decrypter,
        private readonly KeyResolver $keys,
        private readonly array $allowedKeyManagement,
        private readonly array $allowedContentEncryption,
    ) {}

    public function parse(string $compact): ClaimsSet
    {
        $jwe = CompactSerializer::deserialize($compact);

        $signed = $this->decrypter->decrypt($jwe, $this->allowedKeyManagement, $this->allowedContentEncryption, $this->keys);

        self::assertNested($jwe->header);

        $claims = $this->inner->parse($signed);

        self::assertReplicatedClaimsAgree($jwe->header, $claims);

        return $claims;
    }

    /**
     * RFC 7519 §5.2 makes `cty: JWT` the marker that says the plaintext is
     * itself a JWT. Checked after decryption and before the plaintext is
     * treated as one, so a JWE carrying something else entirely — which
     * happens to begin with three base64url segments — is refused for what it
     * says it is rather than admitted for what it looks like.
     *
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function assertNested(array $header): void
    {
        $cty = $header['cty'] ?? null;

        // RFC 7515 §4.1.9: the `application/` prefix is optional on the wire
        // and the comparison is case-insensitive, so `application/jwt` and
        // `JWT` are the same answer. The library's own normaliser decides.
        if (!is_string($cty) || !MediaType::equivalent($cty, 'JWT')) {
            throw new InvalidHeaderException(sprintf(
                'An encrypted token must declare "cty": "JWT" in its outer header (RFC 7519 §5.2); got %s.',
                is_string($cty) ? sprintf('"%s"', $cty) : get_debug_type($cty),
            ));
        }
    }

    /**
     * RFC 7519 §5.3: a claim a sender chose to repeat in the outer header —
     * `iss`, usually, so an intermediary can route without holding a key —
     * must say the same thing there as inside. "Receivers MUST reject JWTs in
     * which the replicated values are not consistent."
     *
     * Compared against the claims the consumer accepted rather than against
     * the ones the token merely carried: the outer header is the half nothing
     * has vouched for, so the comparison is only worth making once the inside
     * has been verified. Names present on one side alone are not constrained
     * by §5.3 and are not looked at.
     *
     * @param array<string, mixed> $header
     *
     * @throws InvalidHeaderException
     */
    private static function assertReplicatedClaimsAgree(array $header, ClaimsSet $claims): void
    {
        $inner = $claims->all();

        foreach (array_intersect_key($header, $inner) as $name => $replicated) {
            if (in_array($name, self::JOSE_HEADER_PARAMETERS, true)) {
                continue;
            }

            if ($replicated !== $inner[$name]) {
                throw new InvalidHeaderException(sprintf(
                    'The outer header of this encrypted token repeats the claim "%s" and disagrees with the token inside it (RFC 7519 §5.3).',
                    $name,
                ));
            }
        }
    }
}
