<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Authorization;

use Medzuch\JwtBundle\Security\User\ProvidesScopes;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Answers `SCOPE_x` checks — `#[IsGranted('SCOPE_users.write')]`,
 * `is_granted('SCOPE_read')` — from the scopes the token granted.
 *
 * Scopes are not roles wearing a different prefix. A role says what someone is
 * and outlives any one token; a scope says what the client holding this token
 * was allowed to ask for on their behalf, and two tokens naming the same person
 * can carry different ones. Mapping scopes into roles collapses that
 * distinction, so `SCOPE_` stays its own namespace.
 *
 * A user that carries no scopes is denied rather than passed over: "this user
 * has no such scope" is an answer, and under the default affirmative strategy a
 * voter of the application's own can still grant.
 */
/**
 * @extends Voter<string, mixed>
 */
final class ScopeVoter extends Voter
{
    public const PREFIX = 'SCOPE_';

    public function supportsAttribute(string $attribute): bool
    {
        return str_starts_with($attribute, self::PREFIX);
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $this->supportsAttribute($attribute);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        if (!$user instanceof ProvidesScopes) {
            return false;
        }

        return in_array(substr($attribute, strlen(self::PREFIX)), $user->scopes(), true);
    }
}
