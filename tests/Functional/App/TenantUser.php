<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\JwtBundle\Security\User\ProvidesScopes;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A user of the application's own, which is the point of `user.mode: custom`:
 * not a JwtUser under another name, but a class that decides for itself what an
 * identity is and what the token granted.
 */
final class TenantUser implements ProvidesScopes, UserInterface
{
    /**
     * @param non-empty-string $identifier
     * @param list<string>     $scopes
     */
    public function __construct(
        private readonly string $identifier,
        private readonly array $scopes,
    ) {}

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return ['ROLE_TENANT'];
    }

    /**
     * @return list<string>
     */
    public function scopes(): array
    {
        return $this->scopes;
    }

    #[\Deprecated]
    public function eraseCredentials(): void {}
}
