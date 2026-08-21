<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Tests\Functional\App;

use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\JwtBundle\Security\User\JwtUserFactoryInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * An application's own mapping: identity is the subject within its tenant, and
 * a token naming no tenant belongs to nobody here.
 */
final class TenantUserFactory implements JwtUserFactoryInterface
{
    public function userFrom(ClaimsSet $claims): UserInterface
    {
        $tenant = $claims->getString('tenant');
        $subject = $claims->subject();

        if (null === $tenant || null === $subject) {
            throw new CustomUserMessageAuthenticationException('The token names no tenant.');
        }

        // Its own class, not a JwtUser: the scopes it reports come from where
        // this application keeps them, which here is the `groups` claim rather
        // than `scope`.
        $groups = $claims->getList('groups') ?? [];

        return new TenantUser($subject . '@' . $tenant, array_values(array_filter($groups, is_string(...))));
    }
}
