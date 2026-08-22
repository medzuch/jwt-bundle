<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Event;

use Medzuch\JwtBundle\Issuer\ReservedClaims;
use Medzuch\JwtBundle\Issuer\TokenIssuance;

/**
 * Dispatched with the claims assembled and nothing signed yet, so a listener
 * can still change what the token will say.
 *
 * The same hook a `TokenClaimProviderInterface` is, for the code that cannot be
 * one: a listener in another bundle, a subscriber that also listens for
 * something else, a decision that belongs to a class the application does not
 * own. It runs after the providers and after the caller's own `issue()` claims,
 * which makes it the last word — deliberately, since "adjust the claims" is
 * only possible for something that sees all of them.
 *
 * The reserved names are refused here rather than after dispatch, so the
 * exception is thrown inside the listener that wrote one and the stack trace
 * names it.
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
        unset($this->claims[$name]);
    }
}
