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
 * README "What a refusal tells the caller" has the rest of the posture — why
 * naming the scope is not a leak, why a denial over anything else is left
 * alone, and why a rule should carry one `SCOPE_*` and nothing else.
 *
 * What is only here: the `scope` parameter is a space-delimited list of
 * RFC 6749 §3.3 scope-tokens, so an attribute carrying a space would arrive at
 * the client as two scopes it never asked about. Anything that is not a
 * scope-token is left out of the header, and a rule with nothing nameable left
 * gets no challenge at all. What the bundle cannot name honestly, it does not
 * name.
 *
 * @internal
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
