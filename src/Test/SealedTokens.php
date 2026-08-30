<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Test;

use Medzuch\Jwt\Algorithm\ContentEncryptionAlgorithm;
use Medzuch\Jwt\Algorithm\KeyManagementAlgorithm;
use Medzuch\Jwt\Jws\CompactJws;
use Medzuch\Jwt\Jwt\NestedJwtBuilder;
use Medzuch\Jwt\Key\Key;

/**
 * How {@see TestTokenFactory} seals what it mints, for a firewall whose
 * consumer reads encrypted tokens (C12).
 *
 * Three settings that are only ever given together — a key-management
 * algorithm, a content-encryption algorithm and the key — held as one, so the
 * factory carries a single extra argument and cannot end up half configured.
 *
 * @internal
 */
final class SealedTokens
{
    public function __construct(
        private readonly KeyManagementAlgorithm $keyManagement,
        private readonly ContentEncryptionAlgorithm $contentEncryption,
        private readonly Key $recipientKey,
    ) {}

    /**
     * The outer header carries the key's `kid` where it has one, because that
     * is what a receiver selects on — for `dir` it is the only thing it can
     * select on. `cty: JWT` is the builder's, and RFC 7519 §5.2 requires it.
     */
    public function seal(CompactJws $signed): string
    {
        $kid = $this->recipientKey->kid();

        return (string) NestedJwtBuilder::wrap(
            $signed,
            $this->keyManagement,
            $this->contentEncryption,
            $this->recipientKey,
            null === $kid ? [] : ['kid' => $kid],
        );
    }
}
