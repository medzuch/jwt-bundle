<?php

declare(strict_types=1);

namespace Medzuch\JwtBundle\Security;

use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

/**
 * Answers a successful login with an RFC 6750 §4 token response.
 *
 * Plugs into any authenticator that takes a `success_handler` — `json_login`
 * and `form_login` both do — so the bundle never owns the login flow itself.
 * The subject is the authenticated user's identifier: whatever the application
 * decided identifies a user is what the token will carry, and what the
 * consumer's `identity_claim` will hand back to the user provider.
 *
 * Only the three RFC 6750 fields are returned. Anything else an application
 * wants in that response — a refresh cookie above all — is its own concern, and
 * deliberately outside this bundle (§8 of the design).
 *
 * @internal
 */
final class AccessTokenSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    public function __construct(private readonly AccessTokenIssuer $issuer) {}

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        $issued = $this->issuer->issue($token->getUserIdentifier());

        $response = new JsonResponse([
            'access_token' => $issued->value,
            'token_type' => 'Bearer',
            'expires_in' => $issued->expiresIn,
        ]);

        // RFC 6749 §5.1: a response carrying a token must not be stored. A
        // cached bearer token is a disclosed one the moment a proxy is in the
        // path.
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
