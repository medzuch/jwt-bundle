<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security\Http;

use Medzuch\JwtBundle\Security\Authorization\ScopeVoter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;

/**
 * Turns a scope denial into the answer RFC 6750 §3.1 describes: `403` with
 * `error="insufficient_scope"` and the scope that would have been enough.
 *
 * Naming the missing scope is deliberate and is not a leak: the client is
 * already authenticated, the scope is one it could have asked its authorization
 * server for, and withholding it leaves a caller retrying a request that can
 * never succeed. What stays unsaid is everything about the token itself.
 *
 * A denial over anything else — a role, an expression, a voter of the
 * application's own — is left alone: this answers `SCOPE_*` and returns null
 * otherwise, which lets Symfony produce its usual 403. An `allow_if` calling
 * `is_granted_scope()` is one of those: what reaches the exception is an
 * `Expression`, not the attribute it asked about, so a rule that wants this
 * header names `SCOPE_*` directly.
 *
 * Several `SCOPE_*` on one rule are listed together. Symfony reads them as
 * alternatives — any one of them grants — while RFC 6750's `scope` parameter
 * reads as what was required, so a rule carrying more than one says something
 * slightly stronger in the header than it means. One scope per rule keeps the
 * two readings the same.
 *
 * The same rule, one strategy along, can say something simply untrue. Under the
 * default `affirmative` strategy a denial means no attribute granted, so every
 * `SCOPE_*` on the rule really is missing. Under `unanimous` or `consensus` a
 * rule mixing kinds — `roles: [ROLE_ADMIN, SCOPE_reports.read]` — can be denied
 * over the role while the scope was granted, and the header then sends a client
 * to its authorization server for a scope it already holds. The bundle cannot
 * tell the two apart: what reaches the handler is the attribute list, not which
 * of them voted no. One scope per rule and nothing else on it is what keeps
 * this header honest under every strategy — and nothing enforces it: what
 * reaches this handler is the attribute list, so a rule mixing kinds is exactly
 * as invisible here as the votes are. It is documentation because it cannot be
 * anything else.
 */
final class InsufficientScopeHandler implements AccessDeniedHandlerInterface
{
    public function __construct(private readonly string $realm) {}

    public function handle(Request $request, AccessDeniedException $accessDeniedException): ?Response
    {
        $scopes = [];

        foreach ($accessDeniedException->getAttributes() as $attribute) {
            if (is_string($attribute) && str_starts_with($attribute, ScopeVoter::PREFIX)) {
                $scopes[] = substr($attribute, strlen(ScopeVoter::PREFIX));
            }
        }

        $scopes = array_values(array_filter($scopes, static fn(string $scope): bool => '' !== $scope));

        if ([] === $scopes) {
            return null;
        }

        return new Response('', Response::HTTP_FORBIDDEN, [
            'WWW-Authenticate' => sprintf(
                'Bearer realm="%s", error="insufficient_scope", scope="%s"',
                Challenge::quote($this->realm),
                Challenge::quote(implode(' ', $scopes)),
            ),
        ]);
    }
}
