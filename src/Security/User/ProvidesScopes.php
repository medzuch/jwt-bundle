<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\User;

/**
 * A user carrying the scopes the token granted.
 *
 * Roles say what someone is; scopes say what the client was allowed to ask for
 * on their behalf. A token minted for a mobile app with `scope: "profile"` and
 * one minted for an admin console with `scope: "profile users.write"` can name
 * the same person, and the difference is not a property of that person.
 *
 * {@see JwtUser} implements this from the token's `scope` claim. An application
 * building its own user — `user.mode: custom` — implements it where it wants
 * `SCOPE_*` checks to work, and in `provider` mode it usually does not: there
 * the store is the authority on what may be done, and a scope from the token
 * would be a second answer to a question already answered.
 */
interface ProvidesScopes
{
    /**
     * @return list<string>
     */
    public function scopes(): array;
}
