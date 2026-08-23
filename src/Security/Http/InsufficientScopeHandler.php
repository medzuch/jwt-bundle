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
 * An attribute that is not a scope is left out of the header, and a rule with
 * nothing nameable left gets no challenge at all: the parameter is a
 * space-delimited list of RFC 6749 §3.3 scope-tokens, and an attribute carrying
 * a space would arrive at the client as two scopes it never asked about. What
 * the bundle cannot name honestly, it does not name.
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
    /** RFC 6749 §3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )` — no space, no quote, no backslash, no controls. */
    private const SCOPE_TOKEN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/';

    public function __construct(private readonly string $realm) {}

    public function handle(Request $request, AccessDeniedException $accessDeniedException): ?Response
    {
        $scopes = [];

        foreach ($accessDeniedException->getAttributes() as $attribute) {
            if (is_string($attribute) && str_starts_with($attribute, ScopeVoter::PREFIX)) {
                $scope = substr($attribute, strlen(ScopeVoter::PREFIX));

                // Only what RFC 6749 §3.3 calls a scope-token gets in. The
                // parameter is a space-delimited list, so an attribute
                // carrying a space would arrive as two scopes, neither of them
                // the one required; a quote or a control character cannot be
                // in the value at all. What the bundle cannot name, it does
                // not name — the same answer it gives a denial with no
                // `SCOPE_*` on it.
                if (1 === preg_match(self::SCOPE_TOKEN, $scope)) {
                    $scopes[] = $scope;
                }
            }
        }

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
