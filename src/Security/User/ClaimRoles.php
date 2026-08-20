<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\User;

use Medzuch\Jwt\Jwt\ClaimsSet;

/**
 * Roles from claims, for a consumer whose tokens carry the authorization.
 *
 * The claim can be a list or a delimited string: `scope` is space-delimited by
 * RFC 6749 §3.3, while `roles` and `groups` are usually arrays, and which one
 * an issuer sends is not something this bundle gets to decide. Both are read;
 * anything else — a number, a nested object, a JSON object with string members
 * — contributes nothing, because a value under some key is not a grant.
 *
 * @internal
 */
final class ClaimRoles
{
    /**
     * @param non-empty-string|null $separator the bundle refuses an empty one at container build,
     *                                         because `explode` has no reading for it
     * @param list<string>          $defaults
     */
    public function __construct(
        private readonly ?string $claim,
        private readonly ?string $separator,
        private readonly string $prefix,
        private readonly array $defaults,
    ) {}

    /**
     * @return list<string>
     */
    public function from(ClaimsSet $claims): array
    {
        $roles = $this->defaults;

        foreach ($this->granted($claims) as $granted) {
            $roles[] = $this->prefix . $granted;
        }

        return array_values(array_unique($roles));
    }

    /**
     * @return list<string>
     */
    private function granted(ClaimsSet $claims): array
    {
        if (null === $this->claim) {
            return [];
        }

        $value = $claims->get($this->claim);

        if (is_string($value)) {
            return null === $this->separator
                ? array_values(array_filter([$value], static fn(string $one): bool => '' !== $one))
                : array_values(array_filter(explode($this->separator, $value), static fn(string $one): bool => '' !== $one));
        }

        // A list, not any array: `{"deep": "value"}` is an object whose member
        // happens to be a string, and reading it as a grant would turn the
        // value of some unrelated key into a role.
        if (!is_array($value) || !array_is_list($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn(mixed $one): bool => is_string($one) && '' !== $one));
    }
}
