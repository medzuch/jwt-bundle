<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\JwtBundle\Issuer\TokenClaimProviderInterface;
use Medzuch\JwtBundle\Issuer\TokenIssuance;

/**
 * The provider an application would write: the tenant a token was minted in,
 * which no call site should have to remember to pass.
 *
 * It records what it was asked about, because the contract is not only "a claim
 * lands in the token" but "a provider is told what is being minted".
 */
final class TenantClaims implements TokenClaimProviderInterface
{
    public ?TokenIssuance $seen = null;

    /**
     * Claims a test wants this provider to contribute besides the tenant —
     * including the ones it is not allowed to.
     *
     * @var array<string, mixed>
     */
    public array $extra = [];

    public function __construct(private readonly string $tenant) {}

    /**
     * @return array<string, mixed>
     */
    public function claimsFor(TokenIssuance $issuance): array
    {
        $this->seen = $issuance;

        return array_replace(['tenant' => $this->tenant], $this->extra);
    }
}
