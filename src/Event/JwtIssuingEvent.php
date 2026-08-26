<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\JwtBundle\Issuer\ReservedClaims;
use Medzuch\JwtBundle\Issuer\TokenIssuance;

/**
 * Dispatched with the claims assembled and nothing signed yet, so a listener
 * can still change what the token will say.
 *
 * The same hook a `TokenClaimProviderInterface` is, for code that cannot be one
 * — a listener in another bundle, a class the application does not own. README
 * "Claims an application adds" has where it sits in the order and why it is
 * last.
 *
 * Reserved names are refused inside the listener that wrote one, so the stack
 * trace names it, and both directions are refused: setting a claim the issuer
 * decides, and *removing* one — deleting the `scope` that `issuers.*.claims`
 * put there would mint a token granting less than the configuration says, and
 * the caller would never learn that it had.
 */
final class JwtIssuingEvent
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly TokenIssuance $issuance,
        private array $claims,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return $this->claims;
    }

    public function setClaim(string $name, mixed $value): void
    {
        ReservedClaims::refuse([$name], 'A listener on JwtIssuingEvent');

        $this->claims[$name] = $value;
    }

    public function removeClaim(string $name): void
    {
        // The same names, for the same reason. Removal is the quieter half of
        // writing: what a listener cannot set, it cannot delete either — and a
        // `scope` that configuration put there is exactly as deliberate as one
        // a listener would replace it with.
        ReservedClaims::refuse([$name], 'A listener on JwtIssuingEvent', 'remove');

        unset($this->claims[$name]);
    }
}
