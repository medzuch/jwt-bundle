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
 *
 * The bare `SCOPE_` is answered too, and denied: no token grants the empty
 * scope, and an attribute nothing else will answer is better refused than left
 * to the access decision manager's default.
 *
 * @extends Voter<string, mixed>
 *
 * @internal
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

    /**
     * The fourth parameter is Symfony 8's `?Vote $vote = null`, which 7.4
     * carries commented out and 6.4 does not have at all — the class itself
     * arrived in 7.3. Typed `mixed` so one signature satisfies all three: a
     * wider parameter type is what overriding allows, and naming the class
     * would be a type that does not exist on the oldest supported line.
     *
     * The wider type closes nothing: `$vote instanceof Vote` is false rather
     * than fatal where the class is absent, so a reason for the denial can be
     * added later without a version-conditional branch.
     */
    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token, mixed $vote = null): bool
    {
        $user = $token->getUser();

        if (!$user instanceof ProvidesScopes) {
            return false;
        }

        return in_array(substr($attribute, strlen(self::PREFIX)), $user->scopes(), true);
    }
}
