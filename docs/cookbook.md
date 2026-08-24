# Cookbook

Recipes that assemble the pieces the [README](../README.md) explains one at a time. Each one is
a task an application has, not a feature the bundle has: what to configure, what to write, and
what the bundle deliberately leaves to you.

Every `medzuch_jwt` block below is compiled into a real container by the test suite, the same as
the README's, so a renamed key cannot leave a recipe describing a bundle that no longer exists.

- [Machine tokens between your own services](#machine-tokens-between-your-own-services)
- [One API, tokens from two issuers](#one-api-tokens-from-two-issuers)
- [One deployment, several tenants](#one-deployment-several-tenants)
- [A browser SPA on a `__Host-` cookie](#a-browser-spa-on-a-__host--cookie)
- [Gating a deploy on the configuration](#gating-a-deploy-on-the-configuration)

## Machine tokens between your own services

Billing calls Ledger. There is no user and no login: the caller *is* the subject, and the token
is minted for one callee at a time.

**On the caller**, an issuer whose `audience` names the callee and whose `ttl` is short — a
machine token is used within seconds of being minted, and nothing refreshes it:

```yaml
# billing/config/packages/medzuch_jwt.yaml
medzuch_jwt:
    keys:
        billing_signing:
            pem_private: '%kernel.project_dir%/config/jwt/billing.pem'
            algorithm: ES256
            kid: billing-2026-01

    issuers:
        outbound:
            issuer: 'https://billing.internal'
            key: billing_signing
            client_id: billing
            audience: 'https://ledger.internal'
            ttl: 120
```

Only an issuer named `default` is reachable by autowiring, so name the service:

```yaml
# billing/config/services.yaml
services:
    App\Ledger\LedgerClient:
        arguments:
            $issuer: '@medzuch_jwt.issuer.outbound'
```

```php
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class LedgerClient
{
    public function __construct(
        private readonly AccessTokenIssuer $issuer,
        private readonly HttpClientInterface $http,
    ) {}

    public function postings(string $account): array
    {
        // The subject is the service, not a person: it is what the callee will
        // log, authorize and rate-limit.
        $token = $this->issuer->issue('svc:billing', scopes: ['postings.read']);

        return $this->http->request('GET', 'https://ledger.internal/postings/' . $account, [
            'auth_bearer' => (string) $token,
        ])->toArray();
    }
}
```

One issuer can address several callees. The configured `audience` is the default, and
`issue('svc:billing', audience: ['https://ledger.internal'])` narrows `aud` for a single token —
so a caller talking to three services needs one issuer and three audiences, not three issuers.

**On the callee**, a consumer that trusts the caller's public key and builds the user from the
token. There is nothing to look up: Ledger has no user store entry for Billing.

```yaml
# ledger/config/packages/medzuch_jwt.yaml
medzuch_jwt:
    keys:
        billing_verify:
            pem_public: '%kernel.project_dir%/config/jwt/billing.pub.pem'
            algorithm: ES256
            kid: billing-2026-01

    consumers:
        internal:
            issuer: 'https://billing.internal'
            audience: 'https://ledger.internal'
            audience_policy: exclusive
            keys: [billing_verify]
            allowed_algorithms: [ES256]
            user:
                mode: claims
```

```yaml
# ledger/config/packages/security.yaml
security:
    firewalls:
        internal:
            pattern: ^/
            stateless: true
            access_token:
                token_handler: medzuch_jwt.handler.internal
```

`mode: claims` builds the user from the token and grants no roles unless you ask for some, so
authorization is a scope question — `#[IsGranted('SCOPE_postings.read')]` on the controller,
answered from the `scope` claim the caller minted. Add `user.roles.defaults` if your access
rules lean on a baseline role; nothing invents one.

`audience_policy: exclusive` is worth having here in a way it rarely is on a public API. A
machine token is minted for one callee by code you control, so a token naming a second audience
is a mistake rather than a legitimate multi-service token — and RFC 9068 §3 asks for exactly one
audience for the reason that a shared token only has to leak from the least careful holder.

**What this bundle does not do here.** Billing mints its own token because it holds a signing
key, which works when both services are yours. Talking to a service that accepts tokens only
from a central authorization server means obtaining one from that server, and fetching, caching
and refreshing it is your code today: the helpers for it — a client-credentials grant, an
outbound `HttpClient` decorator carrying a cached machine token — are §3.6 of
[`docs/plan.md`](plan.md), post-1.0. *Running* that authorization server is a permanent
non-goal (§8).

## One API, tokens from two issuers

Your own tokens on `/api`, a partner's on `/partner`. A consumer names **one** issuer, and a
firewall names **one** token handler, so two token sources are two consumers and two firewalls
— separated by path, host, or anything else `pattern` can express:

```yaml
medzuch_jwt:
    keys:
        own:
            hmac: '%env(JWT_SECRET)%'
            algorithm: HS256

    remote_jwks:
        partner:
            uri: 'https://idp.partner.example/.well-known/jwks.json'

    consumers:
        own_api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [own]
            allowed_algorithms: [HS256]

        partner_api:
            issuer: 'https://idp.partner.example'
            audience: '%env(APP_URL)%'
            remote_jwks: partner
            allowed_algorithms: [RS256, ES256]
            user:
                mode: claims
                identity_claim: sub
                roles:
                    defaults: ['ROLE_PARTNER']
```

```yaml
# config/packages/security.yaml
security:
    firewalls:
        partner:
            pattern: ^/partner(/|$)
            stateless: true
            access_token:
                token_handler: medzuch_jwt.handler.partner_api
        api:
            pattern: ^/api(/|$)
            stateless: true
            access_token:
                token_handler: medzuch_jwt.handler.own_api
```

**The patterns end where the prefix does.** A `pattern` is an unanchored regular expression, so
a bare `^/partner` also matches `/partners`, `/partnership` and anything else starting that way
— which decides who verifies a token on a route nobody meant to include. It matters most where
two prefixes sit beside each other, as they do here.

**A catch-all pattern goes last.** Symfony stops at the first firewall whose `pattern` matches,
so these two can be listed either way round — they are disjoint — while a firewall with
`pattern: ^/` above them would swallow both and every token would be judged by one consumer.

**There is no "try these consumers in turn" mode**, and there will not be one. Falling through
consumers means a token refused by the first is offered to the second, so the reason a token was
refused stops being answerable, and the refusals a caller sees depend on the order of a list.
Two firewalls say the same thing with the route deciding, which is a decision the application
has already made.

If the two token sources genuinely cannot be told apart by the request — the same route serves
both — the bundle cannot do it today: a consumer verifies against one issuer's name and rejects
every other `iss`. The answer is not fall-through but dispatch, choosing the consumer from the
token's `iss` against an allowlist *before* verification, which is C11 in §3.1 of
[`docs/plan.md`](plan.md) — T3, post-1.0.

## One deployment, several tenants

Tokens carry the tenant, and the tenant is part of who the caller is rather than a header the
caller can change.

**Minting**, with a claim provider so every token gets it, whatever mints it:

```php
use Medzuch\JwtBundle\Issuer\TokenClaimProviderInterface;
use Medzuch\JwtBundle\Issuer\TokenIssuance;

final class TenantClaims implements TokenClaimProviderInterface
{
    public function __construct(private readonly TenantContext $tenants) {}

    public function claimsFor(TokenIssuance $issuance): array
    {
        return ['tenant' => $this->tenants->current()->id];
    }
}
```

A provider runs for every configured issuer, so where only some of them are tenant-scoped,
`$issuance->issuerName` says which one is minting and `[]` contributes nothing.

**Verifying**, with a factory that refuses a token whose tenant is not one this deployment
serves. `mode: claims` cannot express it: the user is a subject *within* a tenant, which is two
claims, and a token missing either is for nobody:

```php
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\JwtBundle\Security\User\JwtUserFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

final class TenantUserFactory implements JwtUserFactoryInterface
{
    public function __construct(private readonly TenantDirectory $tenants) {}

    public function userFrom(ClaimsSet $claims): UserInterface
    {
        $tenant = $claims->getString('tenant');
        $subject = $claims->subject();

        if (null === $tenant || null === $subject || !$this->tenants->serves($tenant)) {
            // A valid token for nobody here: an authentication failure, not a
            // server error, and the caller is told no more than `invalid_token`.
            throw new AuthenticationException();
        }

        return new TenantUser($tenant, $subject);
    }
}
```

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'
            algorithm: HS256

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: default
            client_id: '%env(APP_CLIENT_ID)%'
            audience: '%env(APP_URL)%'

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
            user:
                mode: custom
                factory: 'App\Security\TenantUserFactory'
```

The user names itself in `custom` mode — `identity_claim` is not consulted — so
`TenantUser::getUserIdentifier()` can be `acme/user-42`, and the security layer logs, throttles
and audits per tenant without anything else being told about tenants.

**Everything else is a normal authorization question.** The tenant is on the user, so a voter, a
Doctrine filter or a `#[IsGranted]` expression reads it from there.

Scopes stay scopes, but in this mode your class has to say so: the voter behind
[`SCOPE_*` attributes](../README.md#scopes) reads them off the user, so `TenantUser` has to
implement `Medzuch\JwtBundle\Security\User\ProvidesScopes` and return them from `scopes()`.
A user class that does not answers every `SCOPE_*` check with a 403 — the safe answer, and a
confusing one if you were expecting the `scope` claim to be enough. `user.mode: claims` builds a
`JwtUser` that already implements it; a `custom` factory builds whatever you wrote.

**What is not here.** One signing key serves every tenant, and a tenant is a claim rather than
its own issuer. Per-tenant issuers — a different `iss`, a different key, chosen per request — is
C11 in §3.1 of [`docs/plan.md`](plan.md), T3 and post-1.0. Where tenants must not share a key
today, they have to be separate consumers and issuers, named in configuration and selected by
the firewall the request matched — which works when tenants are few and fixed, and does not when
they are rows in a table.

## A browser SPA on a `__Host-` cookie

A single-page application is the one client that cannot hold a bearer token safely: anywhere
JavaScript can read it, an XSS can too. The token goes in an `HttpOnly` cookie instead, and
something has to read it back off the request.

**The bundle reads the cookie; it never sets one.** Setting it belongs to whatever authenticates
the user, so the login success handler is the application's, not `medzuch_jwt.login.<name>`,
which answers with the RFC 6750 JSON body a non-browser client wants:

```php
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

final class SetsTheSessionCookie implements AuthenticationSuccessHandlerInterface
{
    public function __construct(private readonly AccessTokenIssuer $issuer) {}

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        $issued = $this->issuer->issue($token->getUserIdentifier());

        // No token in the body: the SPA never sees it, which is the entire point.
        $response = new JsonResponse(['expires_in' => $issued->expiresIn]);
        $response->headers->set('Cache-Control', 'no-store');

        $response->headers->setCookie(Cookie::create('__Host-jwt')
            ->withValue($issued->value)
            ->withHttpOnly(true)
            ->withSecure(true)
            ->withPath('/')
            ->withSameSite(Cookie::SAMESITE_LAX)
            ->withExpires(time() + $issued->expiresIn));

        return $response;
    }
}
```

**Reading it back**, with an extractor named where Symfony's own would go:

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'
            algorithm: HS256

    token_extractors:
        spa:
            cookie: '__Host-jwt'
            same_site_only: true

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: default
            client_id: '%env(APP_CLIENT_ID)%'
            audience: '%env(APP_URL)%'

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
```

```yaml
# config/packages/security.yaml
security:
    firewalls:
        login:
            pattern: ^/login$
            stateless: true
            json_login:
                check_path: /login
                success_handler: App\Security\SetsTheSessionCookie
        api:
            pattern: ^/api
            stateless: true
            access_token:
                token_handler: medzuch_jwt.handler.api
                token_extractors:
                    - medzuch_jwt.token_extractor.spa
```

Listing extractors replaces Symfony's default rather than adding to it, so a firewall that
should accept a header *and* the cookie has to name both. Put the cookie first when browser
requests are the ones that must work: the chain stops at the first extractor that finds
anything, so a browser sending any `Authorization` header at all — a stale token, a proxy's
`Basic` credential — would otherwise get a 401 with its cookie unread.

**The cookie brings CSRF with it, and nothing here removes that.** A bearer header is immune by
construction: no browser attaches one on its own. A cookie is attached to requests your
application did not initiate, which is what CSRF is. So:

- `SameSite=Lax` at least, `Strict` where the flow allows;
- the `__Host-` prefix, which makes the browser refuse the cookie unless it is `Secure`,
  path-wide and unscoped to a domain — a subdomain you do not control cannot set it;
- CSRF tokens on state-changing routes, the same as any cookie-authenticated application.

`same_site_only: true` makes the extractor ignore the cookie when the browser reports the
request as cross-site (`Sec-Fetch-Site`). It is defence in depth, not a defence: a request
arriving without that header — an older browser, a non-browser client — is not judged, so it
narrows the window rather than closing it.

## Gating a deploy on the configuration

The container refuses to build on a configuration mistake, which catches the deploy before it
starts. What it cannot catch is the material behind the configuration: a key file nobody
deployed, an env variable that is empty in production, an issuer that is unreachable from this
network. Those are factory arguments, so they fail on the first request instead.

`jwt:config:check` builds all of it up front:

```bash
# In the build, where the network is not the point and may not exist
bin/console jwt:config:check --skip-remote

# On the host that will serve traffic, with its keys and its network
bin/console jwt:config:check
```

The exit status is the gate:

| Status | Meaning |
|---|---|
| `0` | Everything configured was built, and every remote set that was not skipped was reached. |
| `1` | Something failed: a key, a consumer, an issuer, an ID-token registration, or a fetch. |
| `2` | Nothing is configured. |

`2` is deliberately not `0`. A deploy step written as `jwt:config:check && deploy` would
otherwise go green on an application whose configuration file was never deployed at all, which
is exactly what an empty configuration looks like from here.

Pair it with `jwt:jwks:dump --compact`, which prints the document the endpoint serves from the
same service, when a build step writes the JWK Set to a file or a CDN: the two cannot drift,
because there is only one of them.
