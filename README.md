# medzuch/jwt-bundle

A Symfony bundle wiring [`medzuch/jwt-php`](https://github.com/medzuch/jwt-php) into Symfony
applications: **issuing** JOSE tokens (RFC 9068 access tokens, OIDC ID tokens, custom JWS/JWE)
and **verifying** them through Symfony's native Security stack — the `access_token` firewall
authenticator, DI, configuration, console and profiler.

Works for any of these roles, in any combination:

- **Resource server** — verify bearer tokens on an API firewall.
- **Authorization server** — mint short-lived access tokens on login.
- **OIDC relying party** — verify a third-party IdP's tokens via cached, rotation-aware JWKS.
- **Service-to-service** — machine tokens between your own services.

> **Status: pre-1.0.** Issuing and verifying work end to end — mint a token on login, verify
> it on a firewall, be authenticated — with HMAC, RSA, EC and Ed25519 keys from PEM or JWK
> sources, key rotation, a JWK Set endpoint and a key-generation command. Federation works
> too: keys fetched from an issuer's `jwks_uri`, with local fallback, and ID tokens verified
> for an OIDC relying party. Nothing about it is stable yet; see
> [`docs/plan.md`](docs/plan.md) for the full design and roadmap.

Requires PHP 8.3 / 8.4 and Symfony 6.4 LTS, 7.4 LTS or 8.x.

## Installation

```bash
composer require medzuch/jwt-bundle:^0.3
```

The constraint is worth pinning that tightly: pre-1.0, a minor release may move the
configuration surface, and the [changelog](CHANGELOG.md) records what changed and how.

Without Symfony Flex, register the bundle yourself in `config/bundles.php`:

```php
return [
    // ...
    Medzuch\JwtBundle\MedzuchJwtBundle::class => ['all' => true],
];
```

## Quickstart

### Verifying tokens — a resource server

You have an API and tokens minted somewhere else (another service, an identity provider, or
this same application). Configure a **key** to verify with and a **consumer** describing what a
token must say:

```yaml
# config/packages/medzuch_jwt.yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
```

Then point a firewall at the consumer's handler:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            access_token:
                token_handler: medzuch_jwt.handler.api
```

That is the whole integration. Symfony's own `access_token` authenticator extracts the bearer
token, the handler validates it and hands back the `sub` claim, and your user provider loads the
user — so authorization keeps reading current state from your database instead of from a token
minted minutes ago.

A token is accepted only if it is signed by a configured key, uses an allowed algorithm, names
the expected issuer and audience, has not expired, and carries the RFC 9068 claim set. Anything
else is a 401; the reason goes to the log, never to the client.

### Issuing tokens — an authorization server

Add an **issuer**, pointing at the key that signs:

```yaml
# config/packages/medzuch_jwt.yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: default
            client_id: '%env(APP_CLIENT_ID)%'
            audience: '%env(APP_URL)%'
            ttl: 900
```

The signing algorithm is not configured here: a key is bound to exactly one algorithm, so
naming it twice could only ever disagree.

Wire the login response and you are done:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        login:
            pattern: ^/login
            stateless: true
            json_login:
                check_path: /login
                success_handler: medzuch_jwt.login.default
```

A successful login now answers with RFC 6750 fields, under `Cache-Control: no-store`:

```json
{ "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJIUzI1NiJ9...", "token_type": "Bearer", "expires_in": 900 }
```

To mint a token yourself — a service account, a token for one specific audience — inject the
issuer:

```php
use Medzuch\JwtBundle\Issuer\AccessTokenIssuer;

public function __construct(private readonly AccessTokenIssuer $issuer) {}

public function mint(): string
{
    $token = $this->issuer->issue(
        subject: 'user-42',
        scopes: ['invoices:read'],
        claims: ['tenant' => 'acme'],
        ttl: 60,
        audience: ['https://reports.example.com'],
    );

    return $token->value;   // $token->expiresIn is what it was actually minted with
}
```

Every argument after `subject` is optional and narrows what configuration already decided.

### Both at once

An application that issues its own tokens and verifies them on its own API needs one key, one
issuer and one consumer that agree on `issuer` and `audience`:

`logger` names any PSR-3 service. The id below assumes MonologBundle with a `jwt` channel
declared (`monolog: channels: [jwt]`); without one, the container will not build. Omit the line
to disable logging entirely.

```yaml
# config/packages/medzuch_jwt.yaml
medzuch_jwt:
    logger: 'monolog.logger.jwt'

    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

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

## Claims an application adds

A token says what its issuer decides it says. Four places decide, and each can override the one
before it.

**Configuration**, for a claim that never changes:

```yaml
# config/packages/medzuch_jwt.yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: default
            client_id: '%env(APP_CLIENT_ID)%'
            audience: '%env(APP_URL)%'
            claims:
                region: eu-central
```

**A claim provider**, for one that has to be looked up. Implement the interface and the bundle
finds it — there is no tag to remember:

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

`$issuance` describes the token being minted — `issuerName`, `subject`, `scopes`, `audience`,
`ttl` and the `jti` it will carry. A provider runs for every issuer, so with more than one
configured, `$issuance->issuerName` is how a provider serving only some of them says so;
returning `[]` contributes nothing. Tag priority orders providers, and the one that runs *later*
wins, as with event listeners.

**The call itself**, for this token only:

```php
$this->issuer->issue('user-42', scopes: ['invoices:read'], claims: ['tenant' => 'acme']);
```

**A listener on `JwtIssuingEvent`**, which runs last because adjusting a claim set means seeing
all of it:

```php
use Medzuch\JwtBundle\Event\JwtIssuingEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
final class StampsTheDevice
{
    public function __invoke(JwtIssuingEvent $event): void
    {
        $event->setClaim('device', $this->devices->currentFor($event->issuance->subject));
    }
}
```

### The claims nobody may contribute

`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `client_id` and `scope` are the issuer's own,
and a provider or a listener returning one throws — naming the class, so the message says where
to go.

The registered claims are set from configuration and from the arguments of `issue()`. The other
two are the reason the list is not simply "the registered claims": to a JWT library `client_id`
and `scope` are ordinary claims, and to RFC 9068 §2.2 they are what the token grants. A provider
runs for tokens it was never asked about, so one quietly rewriting `scope` would widen every
token in the application. Configuration and the `issue()` call may still set them — both are
places where someone decided *this* token deliberately.

### Knowing what was issued

`JwtIssuedEvent` arrives once the token is signed, for audit and metrics:

```php
use Medzuch\JwtBundle\Event\JwtIssuedEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
final class RecordsGrants
{
    public function __invoke(JwtIssuedEvent $event): void
    {
        $this->audit->granted(
            $event->issuance->jti,
            $event->issuance->subject,
            // What the token says, which is the argument unless something
            // deliberately overrode the claim — see below.
            $event->claims['scope'] ?? implode(' ', $event->issuance->scopes),
            $event->issuance->ttl,
        );
    }
}
```

It carries no token. Everything an audit trail needs is on the event already, and a listener
writing what it is handed to a log would otherwise be writing a working credential to a log —
revocation needs the `jti`, and so does anything else that asks about this token later.

It arrives *after* signing, which matters if your listener can fail. A listener that throws — an
audit database that is down being the obvious one — leaves `issue()` raising an exception for a
token that exists and will verify until it expires. Nobody has been given it, so nothing is
exposed; but if you need the stronger guarantee, that no token exists without its audit record,
write the record from a `JwtIssuingEvent` listener instead, where a failure happens before
anything is signed.

`issuance->scopes` is what the call asked for, and `claims['scope']` is what the token ended up
saying. They are the same until something sets the `scope` claim itself — which configuration
and the `issue()` argument may still do, deliberately — so an audit trail that has to agree with
the token reads the claim, as above.


## Keys

A key is bound to exactly one algorithm, and the algorithm decides what material it must be
given: a shared secret for `HS*`, a PEM or a JWK for `RS*` and `ES*`, a JWK for `EdDSA`.

`bin/console jwt:key:generate` writes any of them and prints the configuration that uses it.

### Shared secrets

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'       # or %env(base64:JWT_SECRET)% for a base64 secret
            algorithm: HS256                # HS256 | HS384 | HS512
            kid: ~                          # required once a consumer verifies with two keys it cannot tell apart
```

### RSA and EC keys

The two halves are separate entries, because they are separate things: only the private one can
sign, and only the public one can verify. Each `pem_*` value is either a path to a PEM file or
the PEM itself — told apart by the armour, since no path begins with `-----BEGIN`.

```yaml
medzuch_jwt:
    keys:
        signing:
            pem_private: '%kernel.project_dir%/config/jwt/private.pem'
            pem_passphrase: '%env(JWT_KEY_PASSPHRASE)%'    # omit for an unencrypted key
            algorithm: RS256                               # RS256/384/512 | ES256/384/512
            kid: '2026-01'
        verifying:
            pem_public: '%kernel.project_dir%/config/jwt/public.pem'
            algorithm: RS256
            kid: '2026-01'

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: signing
            client_id: '%env(APP_CLIENT_ID)%'
            audience: '%env(APP_URL)%'

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [verifying]
            allowed_algorithms: [RS256]
```

Generate a keypair with `bin/console jwt:key:generate RS256 --kid 2026-08 --out config/jwt`,
which also prints the block above with the paths filled in, or by hand:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out config/jwt/private.pem
openssl pkey -in config/jwt/private.pem -pubout -out config/jwt/public.pem
```

A resource server verifying someone else's tokens configures only the public half. An
authorization server that does not verify its own tokens configures only the private one.

### JWK keys, and EdDSA

A key can be given as a JWK instead of a PEM — a path to a JSON file or the JSON itself:

```yaml
medzuch_jwt:
    keys:
        signing:
            jwk_private: '%kernel.project_dir%/config/jwt/signing.private.jwk.json'
            algorithm: EdDSA
            kid: '2026-08'
        verifying:
            jwk_public: '%kernel.project_dir%/config/jwt/signing.public.jwk.json'
            algorithm: EdDSA
            kid: '2026-08'
```

**`EdDSA` is configured this way and no other.** RFC 8037 defines Ed25519 as a JWK, and there is
no PEM spelling of it to read; a key bound to `EdDSA` with a `pem_*` source is refused at
container build, saying which source it takes.

A JWK states its own `alg`, `kid` and `use`, and so does the configuration pointing at it. The
two have to agree. What the configuration states and the document leaves out is filled in — a
`kid` in the configuration binds a document that carries none — but a disagreement is refused
when the key is loaded, naming both readings. The configuration is what the container was built
from: which algorithms a consumer can verify and which keys a token can tell apart are answered
from it, and a document that quietly said something else would make those answers describe a
different key than the one signing.

Two refusals worth knowing, because both would otherwise be silent:

- a document carrying `d` behind `jwk_public` — that is the private half, and the JWKS endpoint
  would publish it verbatim, in a document that parses and returns 200;
- a **JWK Set** where a key belongs. It is the document people have on hand, since it is what a
  JWKS endpoint serves, so it is named for what it is rather than reported as a malformed key.

### Generating keys

```bash
bin/console jwt:key:generate RS256 --kid 2026-08 --out config/jwt
bin/console jwt:key:generate EdDSA --kid 2026-08 --format jwk --out config/jwt --name signing
bin/console jwt:key:generate HS256 --name api
```

The command writes the key and prints the `medzuch_jwt` block that uses it — which of the four
sources it belongs in, with both halves and the `kid` already in place. Every key it emits is
built through the same library that reads it back.

A relative `--out` is anchored to `%kernel.project_dir%` in the printed block. The key is read
when the key service is first built, in whatever working directory that process happens to have
— php-fpm's, a worker's — so a path relative to where you ran the console would work locally and
fail on the first request that signs.

Without `--out` the material is printed instead, which puts a private key in your scrollback.
With `--out` it is written to files: the private half readable only by its owner, and neither
half ever overwritten — a key file replaced in place invalidates every token still in flight,
and the second run is the one that would do it silently.

A shared secret is printed as an environment line rather than written to a file, because that is
where the `hmac` source reads it from.

### HMAC secret length

An HMAC secret needs at least 32 bytes of entropy (48 for HS384, 64 for HS512 — RFC 8725 §3.5):

```bash
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

That prints base64, so decode it on the way in with Symfony's `base64:` processor — the two go
together:

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(base64:JWT_SECRET)%'
```

Wiring a base64 string as `%env(JWT_SECRET)%` also works and is not weaker, but then the key
material is the encoded text rather than the bytes you generated, which makes the length rules
above harder to reason about.

The secret stays an environment reference all the way into the key, so it never becomes a
container parameter and never appears in `debug:container` output. The flip side is that its
length cannot be checked when the container is built: too short a secret fails when the key is
first used, not at deploy time.

## Who the token turns out to be

By default the bundle hands the identifier to the firewall's user provider and your store
answers — roles included. Two other modes exist because that answer is not always available.

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%', algorithm: HS256 }

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: ['%env(APP_URL)%']
            keys: [default]
            allowed_algorithms: [HS256]
            user:
                mode: claims            # provider (default) | claims | custom
                identity_claim: sub
                roles:
                    claim: scope        # scope | roles | groups | whatever your issuer sends
                    separator: ' '      # a space is what `scope` uses; null takes the claim whole
                    prefix: 'ROLE_'
                    defaults: ['ROLE_USER']
```

**`claims`** builds the user from the token and consults no store. This is the mode for a
resource server verifying a third party's tokens: there is nothing to look up, the issuer is
the authority, and a local row keyed on `sub` would be a copy that goes stale. The user is a
`JwtUser`, which keeps the whole claim set — so a controller asking which tenant this is asks
`$this->getUser()->claims()` rather than parsing the token again.

Role mapping reads a list claim (`["staff","billing"]`) or a delimited string (`scope`, which
RFC 6749 §3.3 makes space-delimited); both are ordinary, and which one arrives is the issuer's
choice, not yours. Anything else — a number, a nested object — contributes no roles, because a
value under some key is not a grant.

**`custom`** hands the claims to a service of yours:

```php
use Medzuch\Jwt\Jwt\ClaimsSet;
use Medzuch\JwtBundle\Security\User\JwtUserFactoryInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class TenantUserFactory implements JwtUserFactoryInterface
{
    public function userFrom(ClaimsSet $claims): UserInterface
    {
        // the token is already verified here; what is left is the mapping
    }
}
```

The user it returns also names itself — its identifier is what the security layer records, and
`identity_claim` is not consulted in this mode. An identity assembled from several claims is
therefore fine, and so is refusing a token that carries none of them.

```yaml
user: { mode: custom, factory: 'App\Security\TenantUserFactory' }
```

Refusing there means "a valid token for nobody I know", so throw an `AuthenticationException`
— it becomes a 401, not a 500.

Each mode answers the question differently, so an option that names another mode's answer is
refused at container build rather than ignored: a `factory` where nothing calls one, and a
`roles.claim` or `roles.defaults` in a mode where the provider or your factory decides roles.
`roles.separator` and `roles.prefix` are not checked that way — they carry defaults, so a value
set outside `claims` mode is indistinguishable from one never written, and it is simply unread.

`roles.defaults` is empty unless you set it, so `claims` mode grants exactly what the token
carries. If your access rules lean on a baseline like `ROLE_USER`, say so — nothing invents it
for you.

## Where the token comes from

Symfony reads the `Authorization` header by default, and ships extractors for the query string
and a form-encoded body — `security.access_token_extractor.header`, `.query_string`,
`.request_body`. The one it does not ship is the one a browser needs:

```yaml
medzuch_jwt:
    token_extractors:
        spa:
            cookie: '__Host-jwt'
            same_site_only: true
```

```yaml
security:
    firewalls:
        api:
            access_token:
                token_handler: medzuch_jwt.handler.api
                token_extractors:
                    - security.access_token_extractor.header
                    - medzuch_jwt.token_extractor.spa
```

**The order is a decision, not a preference.** Symfony's chain returns the first extractor that
finds anything and stops — so with the header listed first, a browser sending *any*
`Authorization` header, including a stale token or a `Basic` credential from a proxy, gets a 401
while its cookie sits unread. The cookie is an alternative, not a fallback. Put the cookie
extractor first if browser requests are the ones that must work.

A single-page application that keeps its token in JavaScript keeps it where any injected script
can read it. An `HttpOnly` cookie is the safer place for it — and then something has to read the
token back off the request, which the header extractor cannot.

**Read the trade before taking it.** A token in an `Authorization` header is immune to CSRF by
construction: nothing attaches one for you. A cookie is attached by the browser to requests your
application did not initiate, which is precisely what CSRF is. Moving the token into a cookie
buys protection from script access and takes on cross-site request forgery in exchange.

Neither this extractor nor anything else in the bundle closes that on its own. What you need
beside it:

- `SameSite=Lax` at least, `Strict` where the flow allows, set on the cookie by whatever issues
  it — this bundle does not set cookies;
- the `__Host-` prefix, which makes the browser refuse the cookie unless it is `Secure`,
  path-wide and unscoped to a domain, so a subdomain cannot set one for you;
- CSRF protection on state-changing routes, the same as any cookie-authenticated application.

`same_site_only: true` adds defence in depth: when the browser says the request came from
another site (`Sec-Fetch-Site: cross-site`), the cookie is ignored. It is not a CSRF defence —
a request without that header, from an API client or an older browser, is not judged at all —
and it is off by default because it silently drops legitimate cross-site calls in a flow that
means them.

## Scopes

A role says what someone *is*; a scope says what the client holding this token was allowed to
ask for on their behalf. Two tokens naming the same person can carry different ones, so the
bundle keeps them in their own namespace rather than folding them into roles:

```php
#[IsGranted('SCOPE_reports.read')]
public function reports(): Response { … }
```

```yaml
security:
    access_control:
        - { path: ^/api/reports, roles: SCOPE_reports.read }
```

The scopes come from the token's `scope` claim: space-delimited as RFC 6749 §3.3 and RFC 9068
§2.2.3 have it, or a JSON list of strings, which some issuers send instead. Nothing to configure
— the voter answers `SCOPE_*` and only that.

The claim name is `scope` and is not configurable. An issuer that puts scopes somewhere else —
Entra ID's `scp`, say — is read by a `custom` factory, which gets the whole claim set and
decides for itself; that is the same seam the user modes already provide, and one claim name in
configuration would invite a second.

**It needs a user that carries the scopes** — one implementing `ProvidesScopes`. `user.mode:
claims` gives you that; a `custom` factory can implement it on whatever it builds; and a user
loaded from your own store can implement it too, which is the escape hatch if you keep scopes
there.

What the voter looks at is the user, not the mode. So in `provider` mode a `SCOPE_*` check is
refused as long as your user class says nothing about scopes — which is the usual case and the
honest answer rather than a gap: there the store is the authority on what may be done, and a
scope from the token would be a second answer to a question already settled.

**One caveat about strategies.** A user with no scopes is *denied*, not passed over. Under the
default `affirmative` strategy that cannot override another voter's grant, so there is nothing
to switch off. Under `unanimous` or `consensus` this voter votes like any other, and a `SCOPE_*`
check against a user that carries no scopes will veto — which is what those strategies are for,
but worth knowing before you change one.

With `symfony/expression-language` installed, the same check reads as a scope in an expression:

```yaml
security:
    access_control:
        - { path: ^/api/reports, allow_if: "is_granted_scope('reports.read')" }
```

which is `is_granted('SCOPE_reports.read')` with the prefix kept out of the string. Note that a
denial through an expression cannot produce the RFC 6750 `insufficient_scope` header — see
[what a refusal tells the caller](#what-a-refusal-tells-the-caller).

## What a refusal tells the caller

RFC 6750 §3 asks a resource server to answer refusals in a way a client can act on. Symfony
answers one of the three cases on its own — a token it rejects — and the bundle supplies the
other two:

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%', algorithm: HS256 }

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: ['%env(APP_URL)%']
            keys: [default]
            allowed_algorithms: [HS256]
            realm: 'reports-api'        # …and the same string below

security:
    firewalls:
        api:
            entry_point: medzuch_jwt.entry_point.api
            access_denied_handler: medzuch_jwt.access_denied.api
            access_token:
                token_handler: medzuch_jwt.handler.api
                realm: 'reports-api'    # Symfony's own, for the header it sends
```

**Two realms, and they should match.** The rejected-token header is Symfony's, built from
`access_token.realm`, which defaults to *none*; the other two are the bundle's, from
`consumers.<name>.realm`, which defaults to the consumer's name. The bundle cannot set
Symfony's for you without deciding which firewall this consumer belongs to, which is what
[DEC-1](docs/plan.md) exists to avoid — so it is one string written twice.

| The request | Answer | `WWW-Authenticate` |
|---|---|---|
| carried no token | `401` | `Bearer realm="reports-api"` |
| carried one that was not accepted | `401` | `Bearer realm="reports-api", error="invalid_token", error_description="Invalid credentials."` |
| was authenticated but lacked a scope | `403` | `Bearer realm="reports-api", error="insufficient_scope", scope="reports.read"` |

**No `error` on the first row**, which RFC 6750 §3 asks for and is worth the exactness:
`error="invalid_token"` for a request that sent no token describes a failure that did not
happen, and sends the reader looking for a bad token they never had.

**Nothing on the second row says why.** Expired, wrong audience, revoked, signed by a key this
consumer does not accept — all of it is `invalid_token`. The reason is in your log, where it
helps you, rather than on the wire, where it helps someone else.

**The third row names the scope**, and that is not a leak: the caller is already authenticated,
and the scope is one they could ask their authorization server for. Withholding it leaves a
client retrying a request that can never succeed.

A denial over anything else — a role, an expression, a voter of your own — is left alone, so
Symfony's usual 403 stands.

**An `allow_if` is one of those.** What reaches the handler is the expression, not the attribute
it asked about, so `is_granted_scope('reports.read')` gives a plain 403 with no bearer challenge.
A rule that wants the RFC header names the attribute directly — `roles: SCOPE_reports.read`, or
`#[IsGranted('SCOPE_reports.read')]`, both of which carry it.

One scope per rule keeps the header honest, too: Symfony reads several attributes on one rule as
alternatives — any one grants — while RFC 6750's `scope` reads as what was required. And keep it
the *only* attribute on that rule if you have moved off the default `affirmative` strategy: under
`unanimous` or `consensus` a rule like `roles: [ROLE_ADMIN, SCOPE_reports.read]` can be denied
over the role, and the header would then send a client off to fetch a scope it already has. What
reaches the handler is the attribute list, not which of them voted no.

## Knowing why, when the caller is not told

The wire says `invalid_token` for every rejected token, deliberately. Your dashboard needs the
half that is missing there, and two events carry it:

```php
use Medzuch\JwtBundle\Event\JwtRejectedEvent;
use Medzuch\JwtBundle\Security\RejectionReason;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
final class CountsRefusals
{
    public function __invoke(JwtRejectedEvent $event): void
    {
        $this->metrics->increment('jwt.rejected', [
            'consumer' => $event->consumer,
            'reason' => $event->reason->value,
        ]);

        if (RejectionReason::KeysUnavailable === $event->reason) {
            $this->alerts->page('cannot reach the issuer', $event->cause);
        }
    }
}
```

`JwtVerifiedEvent` is the other side: the consumer, the token's claims, and the identity the
request will authenticate as. It carries no token either — but the claims are the token's own, so
a listener that logs them logs whatever they hold: subjects, emails, tenant ids.

| Reason | What happened | What it usually means |
|---|---|---|
| `expired` | `exp` has passed | the ordinary cost of short lifetimes — worth a baseline, not an alert |
| `not_yet_valid` | `nbf` or `iat` is in the future | clock skew; raise `leeway` if it is small and constant |
| `signature_invalid` | no accepted key verifies it | somebody is trying something |
| `unknown_key` | no key matches the token's `kid` | a rotation that has not finished, or another issuer's token |
| `algorithm_refused` | the `alg` is not in `allowed_algorithms` | a client misconfigured, or an algorithm-confusion attempt |
| `wrong_issuer` | `iss` is not the configured one | a token from somewhere else |
| `wrong_audience` | `aud` does not name this consumer, or names another too | the token was minted for a different service |
| `revoked` | a denylist withdrew this `jti` | working as intended |
| `malformed` | not a JWT this consumer can read, `typ` included | a client sending the wrong thing |
| `claims_refused` | a claim is missing, mistyped or refused — the identity claim included | usually a profile mismatch |
| `keys_unavailable` | the key set would not fetch, or what came back is not usable key material | **an outage, not a verdict on the token** |
| `identity_refused` | the token verified and named somebody, and the application refused them | your `custom` factory said no |
| `other` | something with no bucket yet | read `cause` |

The reasons are coarser than the library's exception classes on purpose: a case per exception
would only move the coupling, and a dashboard would have to learn a new name every time the
library grows a leaf. `$event->cause` is the exception itself when you need more than the bucket.

A token that names *nobody* — no `sub`, or no configured `identity_claim` — is `claims_refused`
rather than `identity_refused`: there was no identity to refuse. It reads the same way whether
the claim was missing or held a number, which is the point of a bucket.

**A `custom` factory's own message does reach the client.** Throwing a
`CustomUserMessageAuthenticationException` from `userFrom()` is how you say something specific to
the caller, and the bundle passes it through untouched — deliberately, since the factory is the
only party that knows whether its refusal is safe to explain. Everything else stays behind
Symfony's generic `Invalid credentials.`

**Neither event carries the token.** What was presented is a credential whether or not it
verified here — a revoked token still opens doors elsewhere — so a listener that logs what it is
handed cannot write one into a log.

**Verified is not authenticated.** In `user.mode: provider` and `claims`, Symfony loads the user
after this bundle is done, so a token can be accepted here and the request still fail because
the store has no such user. That refusal is Symfony's `LoginFailureEvent`, not this bundle's.


## Revoking a token

A JWT is valid because it verifies, not because anyone is still willing to accept it — that is
the trade that makes it stateless. When you need the willingness back, give the consumer a
denylist:

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%', algorithm: HS256 }

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: ['%env(APP_URL)%']
            keys: [default]
            allowed_algorithms: [HS256]
            denylist:
                cache_pool: cache.app       # or `cache:` for a PSR-16 service, or `service:` for one of yours
```

Every accepted token has a `jti` — RFC 9068 §2.2 requires it — so it can be named:

```php
use Medzuch\JwtBundle\Revocation\TokenDenylistInterface;

public function logout(TokenDenylistInterface $api, JwtUser $user): Response
{
    $jti = $user->claims()->jwtId();
    $expiresAt = $user->claims()->expiresAt();

    // Both are required of an access token and the consumer refuses one that
    // lacks them, so this is a type guard rather than a real branch.
    if (null !== $jti && null !== $expiresAt) {
        $api->revoke($jti, $expiresAt);
    }
}
```

The argument name is the consumer's name, and `medzuch_jwt.denylist.api` is the service id. A
token you minted carries its id back to you, so a token can also be revoked at the point it was
issued:

```php
$token = $issuer->issue('user-42');
$denylist->revoke($token->jti, new DateTimeImmutable('+' . $token->expiresIn . ' seconds'));
```

**An entry only outlives the token it refuses.** After `exp` the token is refused on its own
terms, so a revocation kept beyond that is a row nobody will ever read — which is why revoking
takes the moment to hold until, and why the shipped implementation is a cache rather than a
table with a schema, a migration and something to sweep it.

Pass the token's own `exp`: the shipped denylist knows the consumer's `leeway` and keeps the
entry that much longer, because a token is accepted until `exp` plus that tolerance and an entry
expiring on the dot would let a revoked token back in for exactly that window.

What that costs is twofold. **A cache flush forgets every revocation** while the tokens they
refused are still valid. And **authentication now depends on the cache being reachable**: a
store that throws takes the request with it, as a 500 rather than a 401. That is the right way
for a revocation check to fail — the alternative is accepting tokens nobody can vouch for while
the store is down — but it is a coupling worth knowing before an outage teaches it. If neither
is acceptable, implement `TokenDenylistInterface` over a store that survives and name it under
`denylist.service`; the rest of the wiring is unchanged.

Configure no denylist and nothing is asked and nothing is registered: revocation is a lookup per
request, and a consumer that does not need it should not pay for it.

## Audience policy

`audience` says which names this application answers to; a token is for it when `aud` names any
of them, which is what RFC 7519 §4.1.3 describes. A consumer can ask for more:

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%', algorithm: HS256 }

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: ['%env(APP_URL)%']
            audience_policy: exclusive     # any (default) | exclusive
            keys: [default]
            allowed_algorithms: [HS256]
```

**`exclusive` refuses a token that is also addressed to someone else.** A token minted for
several services is valid at each of them, so it only has to leak from the least careful one —
their logs, their error tracker, their proxy — to be presented here. RFC 9068 §3 asks access
tokens to name one audience for exactly this reason.

It is off by default because it is a posture rather than a correctness fix: a shared token *is*
a valid token for you, and refusing it is a decision about blast radius that the issuer's
practices have to justify. Turn it on when you can influence what the issuer mints.

Exclusivity is about audiences you did not configure, not about the token naming all of yours:
an application answering to two names is addressed by either.

## Rotating a key

Rotation is a configuration move rather than a feature. An issuer signs with **one** key while a
consumer accepts **several**, so a new key can start signing while tokens from the old one are
still in flight:

1. Add the new keypair alongside the old one, each with its own `kid`
   (`jwt:key:generate <alg> --kid <new-kid> --out config/jwt` writes it and prints the entry).
2. Add the new public half to the consumer's `keys`. Nothing changes yet — the issuer still
   signs with the old key, and both are now accepted.
3. Point the issuer at the new private half. New tokens carry the new `kid`; tokens minted a
   minute ago still verify.
4. Once the longest `ttl` has passed, remove the old key from `keys` and delete it.

```yaml
medzuch_jwt:
    keys:
        signing_2026:  { pem_private: '…/2026.pem',     algorithm: RS256, kid: '2026-01' }
        verify_2026:   { pem_public:  '…/2026.pub.pem', algorithm: RS256, kid: '2026-01' }
        verify_2025:   { pem_public:  '…/2025.pub.pem', algorithm: RS256, kid: '2025-07' }

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: signing_2026          # step 3 changes this line
            client_id: '%env(APP_CLIENT_ID)%'
            audience: '%env(APP_URL)%'

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [verify_2026, verify_2025]
            allowed_algorithms: [RS256]
```

**The `kid`s are what make the overlap work.** Without them the library resolves a token to the
first key bound to its algorithm and does not try the others, so the second key would verify
nothing — which is why a consumer configured that way is refused at container build.

## Publishing a JWK Set

Relying parties that verify your tokens need your public keys. List the ones to publish, and
route to the controller wherever the document belongs:

```yaml
medzuch_jwt:
    keys:
        verify_2026:   { pem_public: '…/2026.pub.pem', algorithm: RS256, kid: '2026-01' }
        verify_2025:   { pem_public: '…/2025.pub.pem', algorithm: RS256, kid: '2025-07' }

    jwks:
        keys: [verify_2026, verify_2025]
        cache_max_age: 300
```

```yaml
# config/routes.yaml
medzuch_jwt_jwks:
    path: /.well-known/jwks.json
    methods: [GET]
    controller: medzuch_jwt.jwks_controller
```

The bundle registers no route of its own: where a JWKS document lives — under `/.well-known/`,
behind a prefix, on a separate host — is the application's decision, and a route the bundle
owned would either take that choice away or duplicate it.

**The route has to be reachable without a token.** That is the entire purpose of the document,
and an `access_control` that starts with a catch-all will serve a relying party a 401 instead:

```yaml
security:
    access_control:
        - { path: ^/\.well-known/jwks\.json$, roles: PUBLIC_ACCESS }
        - { path: ^/, roles: IS_AUTHENTICATED_FULLY }
```

The response carries an `ETag` over the document, so a conditional request gets a `304` and
`cache_max_age: 0` means revalidate rather than refetch.

Only verification halves are published, and **a shared secret is refused at container build**: a
symmetric key's JWK carries the secret itself, so publishing it would hand every reader the key
that signs, in a document that parses perfectly and returns 200.

## Verifying against an issuer's published keys

A resource server that verifies someone else's tokens — an identity provider's, a partner's —
does not have to be redeployed every time they rotate. Point a consumer at their `jwks_uri` and
the keys are fetched and cached:

```yaml
medzuch_jwt:
    remote_jwks:
        partner_idp:
            uri: 'https://idp.example.com/.well-known/jwks.json'
            cache_ttl: 300          # seconds the document is cached
            min_refresh: 60         # shortest interval between refetches on an unknown kid

    consumers:
        partner:
            issuer: 'https://idp.example.com'
            audience: '%env(APP_URL)%'
            remote_jwks: partner_idp
            allowed_algorithms: [RS256]
```

The defaults name Symfony's own services: `psr18.http_client` for the client and `cache.app`
for the cache pool, which is wrapped for the PSR-16 interface the resolver takes. Install
`symfony/http-client` and `psr/http-client` and both are there; name your own with
`http_client`, `request_factory`, `cache_pool` or `cache` if they are not.

**Connection and read timeouts belong to the client.** This bundle cannot impose a socket
timeout on one it does not own, and an identity provider that accepts connections but never
answers is the outage that hurts most — configure `framework.http_client` accordingly.

What the fetching does and does not do:

- **HTTPS only.** A plaintext `uri` is refused. Verification keys taken from a channel an
  attacker can rewrite are not verification keys (RFC 8725 §3.10), and a token's own `jku` is
  never followed.
- **Cached, and refetched sparingly.** The common path touches no network. A token naming a
  `kid` the cached set lacks buys one refetch — the issuer may have rotated — but no more often
  than `min_refresh`, so tokens bearing kids nobody ever published cannot be amplified into a
  fetch storm against the issuer.
- **Bounded.** A response over `max_body_bytes` (256 KB by default) is refused before it is
  parsed.

### Surviving an outage

Name local keys *and* a remote set, and the local ones are tried first:

```yaml
medzuch_jwt:
    keys:
        partner_2026: { pem_public: '…/partner-2026.pub.pem', algorithm: RS256, kid: '2026-01' }

    remote_jwks:
        partner_idp:
            uri: 'https://idp.example.com/.well-known/jwks.json'

    consumers:
        partner:
            issuer: 'https://idp.example.com'
            audience: '%env(APP_URL)%'
            keys: [partner_2026]
            remote_jwks: partner_idp
            allowed_algorithms: [RS256]
```

A token signed with the key you already hold verifies without a round trip, and keeps verifying
while the issuer is unreachable. A token signed with a key they have rotated to since falls
through to the fetched set. That is the whole of it: no failover mode to configure, and nothing
that behaves differently on the day the identity provider is down.

**What you pay for it:** a key configured here is outside the issuer's rotation. When they drop
it from their JWK Set — because it expired, or because it leaked — tokens signed with it keep
verifying against your copy until you delete the entry. That is the same property that makes an
outage survivable, seen from the other side, so configure local keys for the keys you want to
outlive an outage, and let the rest come from the endpoint.

With a remote set configured, the build-time check that every allowed algorithm has a key
behind it is not made — the issuer publishes their algorithms at runtime and may rotate to one
this application has never seen, so the question has no answer while the container is built.

## Verifying an ID token (OIDC relying party)

An ID token is what an identity provider hands your application at the end of a login, saying
who just authenticated. Register the provider and the client you are registered as:

```yaml
medzuch_jwt:
    remote_jwks:
        partner_idp:
            uri: 'https://idp.example.com/.well-known/jwks.json'

    id_tokens:
        partner:
            issuer: 'https://idp.example.com'
            client_id: '%env(OIDC_CLIENT_ID)%'
            remote_jwks: partner_idp
            allowed_algorithms: [RS256]
```

Then verify it where you already are — in the callback that received it:

```php
use Medzuch\JwtBundle\Oidc\IdTokenVerifier;

public function callback(Request $request, IdTokenVerifier $partner): Response
{
    $claims = $partner->verify(
        $idToken,
        $request->getSession()->remove('oidc_nonce'),   // the value you sent with the authentication request
    );

    $subject = $claims->getString('sub');   // who the provider says this is
    // …find or create your own user for that subject, then log them in
}
```

The argument name is the registration name: `IdTokenVerifier $partner` gets the `partner`
registration, because the bundle registers an alias for it. The service id is
`medzuch_jwt.id_token.partner` if you would rather fetch it.

**There is no firewall authenticator for ID tokens, deliberately.** An ID token says who
authenticated *to the client that asked for it*; it is not a bearer credential for an API, and
accepting one as such is exactly the confusion RFC 9068 exists to end — a token minted for a
browser session would authorise a machine call. The bundle therefore gives you a service to call
at the point where an ID token legitimately arrives, and nothing that can be wired into
`access_token`.

**Pass the nonce you sent.** It is per-authentication-request, so it cannot live in
configuration; keep it in the session between the authentication request and the callback. An
authorization-code flow that sent a nonce and then does not check it has no replay defence (OIDC
Core §3.1.3.7). Omitting the argument skips the check, which is right only for a flow that sent
none.

What is checked: signature and algorithm, `iss`, `aud` against your `client_id`, `azp` when the
token names more than one audience, `exp`/`iat`, the claims OIDC requires, and the `nonce` when
you pass one. **`at_hash` is not** — binding an ID token to an access token needs support the
library does not have yet, and this bundle does not reimplement crypto its library is missing.

## From the console

Four commands, and none of them a second implementation of anything: each asks the services your
application already has.

```bash
# Mint a token through a configured issuer
bin/console jwt:token:create alice --scope reports.read --ttl 60

# Capture it, then ask what a consumer makes of it
TOKEN=$(bin/console jwt:token:create alice --raw)
bin/console jwt:token:inspect "$TOKEN"

# Or pipe it straight through
bin/console jwt:token:create alice --raw | bin/console jwt:token:inspect -
```

`jwt:token:create` calls `AccessTokenIssuer::issue()`, so the token it prints is the token your
application would have minted: the configured key signs it, the configured audience and client
id are on it, and your claim providers and `JwtIssuingEvent` listeners run. Every option after
the subject narrows what configuration decided, exactly as the method's arguments do. It appears
only where an issuer is configured — an application that mints nothing has no use for it — and
`--issuer` can be left out where one issuer is configured, whatever it is called.

`--claim` carries the claims the issuer does not set itself. The registered ones (`iss`, `sub`,
`aud`, `exp`, `nbf`, `iat`, `jti`) come from the arguments and are refused here rather than deep
in a builder; `client_id` and `scope` are accepted and override the configured client id and
`--scope`, which is the issuer's own rule for a caller's claims.

`jwt:token:inspect` does two things, and the first needs no configuration at all. It decodes:
header, claims, and the moments among them rendered as moments, so `exp` reads *expired 4 minutes
ago* rather than as a number. Then, given a consumer, it verifies — through that consumer's own
handler, which is what makes the answer worth having, and it names the reason a refusal would
never put on the wire:

```
 [ERROR] Consumer "api" refuses this token: expired
```

The exit status is scriptable: `0` accepted, or decoded where the application configures no
consumer at all; `1` refused; `2` nothing to inspect — not a JWT, no token, no such consumer, or
several configured and none named. That last one is deliberately not a pass: `jwt:token:inspect
"$TOKEN" && deploy` should not go green having verified nothing.

Two consequences of verifying through the real path, both deliberate. Your listeners see an
inspection as they would a request, so a metrics listener counts it — an answer reached by a
second, quieter route would be worth much less than one that agrees with your firewall. And with
several consumers configured the command will not pick one for you: name it with `--consumer`.

`--consumer` names an **access-token** consumer. An ID token still decodes — that half needs no
configuration — but a consumer asked to verify one refuses it as `malformed`, because `typ` says
it is not the kind of token that consumer reads. ID tokens are verified by `IdTokenVerifier`
from your callback, not by a firewall (DEC-8).

*Would* authenticate is the exact word: for `user.mode: provider` and `claims`, the identity is
loaded by Symfony after the handler returns, so the command can accept a token naming a user your
store no longer has. It is the same "verified, not authenticated" line `JwtVerifiedEvent` draws.

`jwt:jwks:dump` prints the document `medzuch_jwt.jwks_controller` serves — the same `JwkSet`
service, so the two cannot drift apart. Indented for reading, `--compact` for byte-for-byte:

```bash
bin/console jwt:jwks:dump --compact > public/.well-known/jwks.json
```

which is what it is for. An application publishing its keys from a file or a CDN rather than from
the endpoint needs the document without needing the route, and writing one by hand is how a `kid`
comes to disagree with the key it names. It appears only where `medzuch_jwt.jwks` has keys in it.

Serving the file yourself means serving the headers the endpoint sets for you: `Content-Type:
application/jwk-set+json` (RFC 7517 §8.5), a cache lifetime, and an `ETag`. Most relying parties
accept `application/json`; the strict ones are the reason to set it.

`jwt:key:generate` is the fourth — see [Generating keys](#generating-keys).

**A minted token is a working credential** for as long as it lives. It is on your screen and in
your shell history; `--raw` at least keeps the surrounding text out of a log.


## Configuration reference

The complete tree, with every option, default and explanation, is generated from the bundle
itself:

```bash
bin/console config:dump-reference medzuch_jwt
```

That output is always accurate for the version you have installed, which a hand-written
reference in this file would not be.

## Mistakes it refuses to boot with

Configuration errors fail when the container is built, naming the key at fault, rather than
looking like rejected tokens at runtime:

- a consumer or issuer naming a key that does not exist
- an allowed algorithm with no key behind it — a token using it could never be verified
- two keys in one consumer's set that a token cannot tell apart: sharing a `kid`, or sharing an
  algorithm with no `kid`
- a key given the wrong kind of material for its algorithm — a secret for `RS256`, a PEM for
  `HS256` or for `EdDSA`, more than one kind at once, or none
- a consumer verifying with a private-only key, or an issuer signing with a public-only one
- a JWK Set publishing a shared secret, a key with no public half, or a key that does not exist
- a static claim named `iss`, `sub`, `aud`, `exp`, `nbf`, `iat` or `jti` — those are set from
  configuration or by the profile
- a YAML map where a sequence is expected, an unknown algorithm name, leeway above the
  library's ceiling

A JWK is read when the key is first built rather than when the container is compiled — the
document stays a path or an environment reference so it never lands in the compiled container —
so what it says is checked there: a document disagreeing with the configuration about `alg` or
`kid`, a private JWK where the public half belongs, or a JWK Set where a key does.

## What it deliberately does not do

Refresh-token storage and rotation, user entities and login forms, OAuth 2.0 authorization-server
machinery (consent, grants, PKCE), and session-based authentication are all outside this package.
Section 8 of [`docs/plan.md`](docs/plan.md) explains why for each.

## Documentation

- [`docs/plan.md`](docs/plan.md) — the design, the feature catalogue with priority tiers, the
  recorded decisions, and the roadmap.
- [`CHANGELOG.md`](CHANGELOG.md) — what has landed so far.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to work on it.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability. Not through a public issue.

## License

MIT — see [LICENSE](LICENSE).
