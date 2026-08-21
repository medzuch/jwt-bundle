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
 * otherwise, which lets Symfony produce its usual 403.
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
                $this->realm,
                implode(' ', $scopes),
            ),
        ]);
    }
}
