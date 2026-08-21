<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\User;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The user a verified token describes, for applications that have no user
 * store to look one up in.
 *
 * A resource server verifying a third party's tokens usually has nothing to
 * load: the token is the record, the identity provider is the authority, and a
 * local row keyed on `sub` would be a copy that goes stale. This is the user
 * for that case — the claims that arrived, and the roles derived from them.
 *
 * The whole claim set is kept rather than the two fields the security layer
 * needs, because a controller asking "which tenant is this" is asking the token
 * and would otherwise have to parse it a second time.
 */
final class JwtUser implements ProvidesScopes, UserInterface
{
    /** @var non-empty-string */
    private readonly string $identifier;

    /**
     * @param list<string> $roles
     */
    public function __construct(
        string $identifier,
        private readonly array $roles,
        private readonly ClaimsSet $claims,
    ) {
        // Symfony's contract, and a real invariant: an empty identifier makes
        // an anonymous request indistinguishable from an authenticated one in
        // logs and in `is_granted`. It can only arrive from a factory of the
        // application's own, which is where saying so is useful.
        if ('' === $identifier) {
            throw new \InvalidArgumentException('A user identifier cannot be the empty string.');
        }

        $this->identifier = $identifier;
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    public function claims(): ClaimsSet
    {
        return $this->claims;
    }

    /**
     * The `scope` claim, which RFC 6749 §3.3 makes a space-delimited string and
     * RFC 9068 §2.2.3 carries into an access token under that name. Read
     * directly rather than through configuration: an issuer sending scopes
     * somewhere else is one whose grants the role mapping can pick up, and two
     * configurable spellings of the same idea would be one too many.
     *
     * @return list<string>
     */
    public function scopes(): array
    {
        $scope = $this->claims->getString('scope');

        if (null === $scope) {
            return [];
        }

        return array_values(array_filter(explode(' ', $scope), static fn(string $one): bool => '' !== $one));
    }

    /**
     * Nothing to erase: this user is built from a token that was already
     * verified, and holds no credential. Declared because Symfony 6.4 and 7.4
     * require it; 8.0 dropped it from the interface, where it is simply an
     * extra method.
     *
     * The attribute is how 7.3+ is told the implementation is empty rather
     * than forgotten — `AuthenticatorManager` looks for it by name and skips
     * the deprecation. `\Deprecated` is a PHP 8.4 class and this package also
     * runs on 8.3, where nothing resolves it: the attribute is read by name
     * through reflection and never instantiated.
     */
    #[\Deprecated]
    public function eraseCredentials(): void {}
}
