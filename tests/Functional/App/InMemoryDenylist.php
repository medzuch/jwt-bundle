<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use DateTimeImmutable;
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;

/** A store of an application's own, which is what `denylist.service` is for. */
final class InMemoryDenylist implements TokenDenylistInterface
{
    /** @var array<string, DateTimeImmutable> */
    private array $revoked = [];

    public function revoke(string $jti, DateTimeImmutable $until): void
    {
        $this->revoked[$jti] = $until;
    }

    public function isRevoked(string $jti): bool
    {
        return isset($this->revoked[$jti]);
    }
}
