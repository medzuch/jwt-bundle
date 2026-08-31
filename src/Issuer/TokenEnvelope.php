<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Issuer;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\JwtParser;
use Medzuch\Jwt\Jwt\NestedJwtBuilder;
use Medzuch\Jwt\Key\Key;

/**
 * Seals a signed token inside a JWE: the sign-then-encrypt half of an
 * RFC 7519 §5.2 nested JWT (I8), and the mirror of what a consumer with a
 * `jwe` block opens (C12).
 *
 * Sign first, then encrypt, is the order RFC 7519 §11.2 asks for and the only
 * order this can express — what it takes is a {@see CompactJws}, so there is no
 * way through it to encrypt something nothing has signed.
 *
 * Three settings that are only ever given together — a key-management
 * algorithm, a content-encryption algorithm and the recipient's key — held as
 * one object, so an issuer carries a single extra argument and cannot end up
 * half configured. Singular where the reading side is plural: a receiver has to
 * accept every algorithm and key its senders might still be using, while a
 * sender picks one of each and uses it.
 *
 * @internal
 */
final class TokenEnvelope
{
    /**
     * @param list<string> $replicatedClaims claim names copied into the outer
     *                                       header per RFC 7519 §5.3
     */
    public function __construct(
        private readonly KeyManagementAlgorithm $keyManagement,
        private readonly ContentEncryptionAlgorithm $contentEncryption,
        private readonly Key $recipientKey,
        private readonly array $replicatedClaims = [],
    ) {}

    /**
     * The outer header carries the key's `kid` where it has one, because that
     * is what a receiver selects on — for `dir` it is the only thing it can
     * select on. `cty: JWT` is the builder's, and RFC 7519 §5.2 requires it.
     */
    public function seal(CompactJws $signed): string
    {
        $kid = $this->recipientKey->kid();

        $header = null === $kid ? [] : ['kid' => $kid];

        return (string) NestedJwtBuilder::wrap(
            $signed,
            $this->keyManagement,
            $this->contentEncryption,
            $this->recipientKey,
            [...$header, ...$this->replicate($signed)],
        );
    }

    /**
     * The claims to repeat in the outer header, read back out of the token
     * that was just built rather than assembled a second time from what went
     * into it.
     *
     * RFC 7519 §5.3 requires the copy to equal the claim, and the receiver
     * compares the two exactly — a `aud` of `["api"]` beside an outer `"api"`
     * is a disagreement. Reading the built token is what makes the two the
     * same value by construction, whatever shape the builder chose. Parsing
     * here does not verify anything and does not need to: the signature over
     * these bytes was made one line earlier by this process.
     *
     * A configured name the token does not carry is not written. §5.3 governs
     * a claim that was repeated, and a header member with no claim behind it
     * is not one — the receiver would not compare it, so writing it would put
     * an unauthenticated value on the wire that says nothing.
     *
     * @return array<string, mixed>
     */
    private function replicate(CompactJws $signed): array
    {
        if ([] === $this->replicatedClaims) {
            return [];
        }

        $claims = JwtParser::parse((string) $signed)->unverifiedClaims->all();

        return array_intersect_key($claims, array_flip($this->replicatedClaims));
    }
}
