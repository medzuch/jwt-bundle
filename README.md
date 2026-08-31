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

> **Status: 1.0.** Issuing and verifying work end to end — mint a token on login, verify it on
> a firewall, be authenticated — with HMAC, RSA, EC and Ed25519 keys from PEM or JWK sources,
> key rotation, a JWK Set endpoint and a key-generation command. Federation works too: keys
> fetched from an issuer's `jwks_uri`, with local fallback, and ID tokens verified for an OIDC
> relying party. The surface is now covered by a policy rather than by good intentions —
> [`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md) says what will and will not break,
> and the suite holds the package to it. See [`docs/plan.md`](docs/plan.md) for the full design
> and what comes after 1.0.

Requires PHP 8.3 / 8.4 and Symfony 6.4 LTS, 7.4 LTS or 8.x.

## Installation

```bash
composer require medzuch/jwt-bundle:^1.0
```

A caret is enough from here: [`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md) says what
the package will and will not break within a major, and the suite holds it to that. The
[changelog](CHANGELOG.md) records what changed; [`UPGRADE.md`](UPGRADE.md) records what to do
about it, version to version.

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

That `access_token` is whatever the issuer mints. An issuer with a `jwe` block seals what it
signs, so the same field then carries a five-segment JWE rather than the three-segment JWS above
— the handler passes it through either way, and RFC 6750 says nothing about its shape.

**The handler mints from the identity and nothing else.** It calls `issue()` with the user
identifier, so the token carries what configuration decided — audience, TTL,
`issuers.<name>.claims` — plus whatever your claim providers and `JwtIssuingEvent` listeners add.
What it cannot do is give *this* login different scopes from the next one: per-user scopes are an
argument to `issue()`, and this handler has no way to be told them. Static scopes for every token
one issuer mints are configuration (`issuers.<name>.claims`); scopes that depend on who just
logged in need a success handler of your own, calling the issuer as below.

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

### The other three roles

**An OIDC relying party** verifies a provider's ID tokens where they arrive — the login callback
— rather than on a firewall, and is configured differently enough to have its own section:
[Verifying an ID token](#verifying-an-id-token-oidc-relying-party).

**A security event transmitter or receiver** mints and accepts RFC 8417 SETs — RISC and CAEP
events — which travel between an identity provider and the applications that trust it, outside
any login and authenticating nobody:
[Sending and receiving security events](#sending-and-receiving-security-events).

**Service-to-service** is the configuration above with no user behind the token: the caller is
the subject, and the callee is the `audience`. The
[cookbook](docs/cookbook.md#machine-tokens-between-your-own-services) walks both halves.

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
anything is signed. That trade has two sides and neither is free: auditing before signing records
tokens that were never minted if signing then fails, auditing after it misses tokens that were.
Which of "records with no token" and "tokens with no record" your auditors can live with is the
question, and only you can answer it.

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

**Use the reference, not the value.** Every `hmac`, `pem_*` and `jwk_*` key accepts the material
written out in full, and a `pem_*`/`jwk_*` one accepts a path — but only the reference and the
path keep the material out of the compiled container. Written literally into
`config/packages/`, it reaches the container as a factory argument and
`debug:container --show-arguments` will print it, because it was already sitting in a file on the
same disk. What holds either way: the bundle never copies key material into a container
parameter, never logs it, never shows it in the profiler, and never quotes it back in an error —
a value that is neither a readable path nor a recognisable document is reported by its size, so a
key that lost its `-----BEGIN` line on the way through a pipeline does not end up in your logs.

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

**An empty `prefix` is a statement about the issuer, not a formatting choice.** Roles are built
by writing the prefix in front of what the claim says, so with the default `ROLE_` an issuer
sending `admin` grants `ROLE_admin`, and one sending `ROLE_ADMIN` grants `ROLE_ROLE_ADMIN` —
the prefix is a namespace your issuer cannot write its way out of. Set it to `''` and the claim
names your roles directly: an issuer that can put `ROLE_ADMIN` in a token is an issuer that can
make anybody an administrator of this application.

That is the correct behaviour for `claims` mode, where the issuer *is* the authority and the
token is the record — it is the reason the mode exists. It is worth setting deliberately rather
than to make a role name look tidy, and it is worth asking, before you do, whether every party
that can sign for this issuer is one you would hand that to. If the answer is no, keep a prefix
and map the claim to roles you control, or use `custom` and decide in your own factory.

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

## Endpoints that work with or without a token

A public page that shows more to someone who is signed in needs identity to be *optional*: read
the token when there is one, and answer anyway when there is not. That needs no configuration in
this bundle and no authenticator of its own — leave the path behind the same firewall and exempt
it from the access rule:

```yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            access_token:
                token_handler: medzuch_jwt.handler.api

    access_control:
        - { path: ^/api/articles, roles: PUBLIC_ACCESS }
        - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }
```

**The exemption has to come before the catch-all.** `access_control` stops at the first rule
whose `path` matches, so the two lines above reversed would put every `/api` path behind
`IS_AUTHENTICATED_FULLY` and the optional one would never be reached — the same trap the JWK Set
section describes, and the one most likely to survive a copy-paste.

The exemption is the *access rule*, not the firewall. Symfony's `access_token` authenticator
does not fail a request that carries no token — it declines to handle it — so what turns an
anonymous caller away is the rule, and a path the rule does not cover is served to everyone.
A firewall with no catch-all rule needs no exemption at all: it already behaves this way.

In the controller, `Security::getUser()` returns the user or `null`:

```php
public function __invoke(Security $security): JsonResponse
{
    $reader = $security->getUser();

    return new JsonResponse([
        'articles' => $this->articles->visibleTo($reader),
        'draftsVisible' => null !== $reader,
    ]);
}
```

**A token that is present but not valid is still refused.** Optional means the caller may decline
to say who they are — not that saying it wrongly is the same as saying nothing. An expired token
on one of these paths answers `401` with `WWW-Authenticate: Bearer … error="invalid_token"`,
not the anonymous page, so a client whose session lapsed is told to refresh rather than left
wondering where their name went. That is RFC 6750 §3, and it is what stops a stale token from
silently becoming a downgrade.

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
reaches the handler is the attribute list, not which of them voted no. Nothing enforces this:
access rules are the application's, and a bundle that cannot see which voter refused cannot see a
rule mixing kinds either — which is why it is written here rather than checked at build.

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
| `too_old` | `iat` is further back than `max_token_age` allows, `exp` notwithstanding | this consumer's ceiling, not the issuer's lifetime |
| `signature_invalid` | no accepted key verifies it | somebody is trying something |
| `decryption_failed` | an encrypted token's outer layer would not open | the sender and this consumer disagree about which key is current, or the ciphertext was altered |
| `unknown_key` | no key matches the token's `kid` | a rotation that has not finished, or another issuer's token |
| `algorithm_refused` | the `alg` is not in `allowed_algorithms` | a client misconfigured, or an algorithm-confusion attempt |
| `wrong_issuer` | `iss` is not the configured one | a token from somewhere else |
| `wrong_audience` | `aud` does not name this consumer, or names another too | the token was minted for a different service |
| `revoked` | a denylist withdrew this `jti` | working as intended |
| `malformed` | not a JWT this consumer can read, `typ` included — and, for an encrypted consumer, a missing or wrong `cty`, a replicated claim that disagrees, or a bare signed token where a JWE was expected | a client sending the wrong thing |
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


## What ends up in the log

`logger` names a PSR-3 service and the library writes to it — a redacting log that never carries
a token, a key or a claim value. What it does carry is an outcome per verification, and on a busy
API that is a line per request. `log_levels` is where you decide which of those your logger
keeps:

```yaml
medzuch_jwt:
    logger: 'monolog.logger.jwt'

    log_levels:
        accepted: debug                  # a line per request; debug by default
        verification_failed: warning     # bad signature, refused algorithm
        claim_rejected: notice           # expired, wrong audience, missing claim
        key_resolution: debug            # a remote set fetched or served from cache
        key_resolution_failed: warning   # an issuer this application cannot reach
        decrypted: debug                 # an encrypted token opened
        decryption_failed: warning       # one that would not open
```

Every one of them is optional and each keeps the library's default when left out — the defaults
above are those. **The library decides the level; your logger decides whether to record it**, so
raising `claim_rejected` to `warning` is how a refusal becomes something Monolog will page on,
and leaving `accepted` at `debug` is how it stays out of production.

**Set them where they change what you keep, not everywhere.** `verification_failed` and
`key_resolution_failed` are the two worth watching: one is somebody trying something, the other
is an outage on the issuer's side rather than a verdict on any token.

**An `accepted` line is not a request that was allowed through.** It says the library finished
with the token in front of it, and this bundle then goes on asking: a denylist can withdraw it,
`max_token_age` can refuse it, an `exclusive` audience can, a `custom` factory can, and on an
encrypted consumer a replicated claim that disagrees with the token inside can. So one request
may emit `decrypted`, then `accepted`, and still end in a 401 — alerting that treats the accepted
line as the verdict will count refusals as successes. `JwtVerifiedEvent` is what only fires when
the whole of this bundle is satisfied.

The setting is application-wide: it reaches every consumer, every ID-token registration and every
remote JWK Set at once, so two consumers in one application cannot be logged at different levels.
Levels with no `logger` are refused at container build — nothing would emit at them. The last two
are emitted only by a consumer configured with a `jwe` block; nothing else in this bundle
decrypts anything.

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

The other side of that: **revoking with a moment already past writes nothing at all.** There is
nothing to refuse — the token is expired and refused on its own terms — so the call returns
without touching the store. Worth knowing if you are looping over a user's tokens and counting
what you revoked; the expired ones are not in that count.

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

## A token type of your own

The bundle verifies RFC 9068 access tokens because that is what a bearer token on an API is
supposed to be. Where an application has minted something else — a session token, an internal
envelope, a transitional format from before there was a standard to follow — a consumer can name
the `typ` it expects instead:

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%', algorithm: HS256 }

    consumers:
        sessions:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
            token_type: 'vnd.acme.session+jwt'      # instead of RFC 9068's at+jwt
            required_claims: [exp, sub, session_id]
```

**Naming a `token_type` replaces the profile, not the consumer.** Keys, algorithms, `issuer`,
`audience`, `audience_policy`, `leeway`, `max_token_age`, the denylist, user resolution, the
scope voter, the RFC 6750 answers, the events and the profiler panel are all exactly as they
were. What changes is the posture: the token is verified as a plain JWT bearing that `typ`, with
`required_claims` in place of the access-token profile's own list — no `client_id`, no `jti`, no
`at+jwt`.

**Left out, `required_claims` is `["exp"]`.** Only presence is checked; what a value means is
yours. That default is there because the library checks `exp`, `nbf` and `iat` where a token
carries them and nowhere else — so a posture requiring none of them would accept a bearer
credential that never stops being valid, one that lives until somebody rotates a key.

**A list of your own replaces it, `exp` included.** Writing `required_claims: [sub, session_id]`
is writing a consumer that does not require an expiry, which is why it is refused at container
build unless something else bounds the token:

```yaml
token_type: 'vnd.acme.session+jwt'
required_claims: [sub, session_id]
max_token_age: 300      # now something does
```

Dropping `exp` is a real thing to want — a token bounded by its age instead of by a claim — and a
token bounded by nothing at all is far likelier to be an oversight than a decision.

**A denylist needs `jti`.** RFC 9068 requires it, so a denylist on the default posture always has
something to look up; a type of your own need not carry one, and a consumer that cannot name a
token cannot revoke it. Configuring both without `jti` in the list is refused at container build,
rather than refusing every well-formed token at runtime with a message about the token.

**Two spellings are refused for naming something other than what they look like.** `at+jwt` is
what the default posture verifies — naming it here would check *fewer* rules than leaving the key
out, while reading like an explicit opt-in to RFC 9068 — and `JWT` is RFC 7519's generic type.
A `token_type` must also be a literal rather than an `%env()%` reference, the same as
`consumers.*.realm`: Symfony reads a placeholder as the empty string while validating, and a
service wiring is not a deployment variable.

**Give the type as it goes on the wire.** RFC 7515 §4.1.9 puts the bare form in the header, so
`application/vnd.acme.session+jwt` is refused at container build: it would match nothing any peer
ever sends. `vnd.acme.session+jwt` is the same media type spelled the way it arrives.

**`required_claims` is not where identity is decided.** `user.identity_claim` — `sub` by default
— is read after verification, so a list omitting it builds a consumer that verifies a token and
then refuses it for naming nobody. Add whatever your users are identified by.

**`TestTokenFactory` mints `at+jwt` and nothing else**, so the helper shipped in `src/Test/`
cannot produce a token this consumer accepts. Test a custom type by minting with the library's
`JwtBuilder` directly, which is what this bundle's own suite does.

**One thing is thinner than on the RFC 9068 path.** A token too malformed to parse at all is not
written to your log — the library logs that from inside its profile consumers, and a custom
posture is assembled from the layer below them. The refusal still reaches `JwtRejectedEvent` and
the profiler as `malformed`; it is the log line that is missing, and a listener on that event is
where to put one back.

## Several issuers behind one firewall

One API, several tenants — or several identity providers, or a partner alongside your own
issuer. Each mints tokens with its own keys, its own `iss`, and possibly its own idea of what a
user is. A consumer answers to exactly one issuer, which is what makes it safe; a dispatcher puts
several of them behind one firewall and lets the token say which one judges it:

```yaml
medzuch_jwt:
    keys:
        acme: { hmac: '%env(ACME_SECRET)%' }
        globex: { hmac: '%env(GLOBEX_SECRET)%' }

    consumers:
        acme:
            issuer: '%env(ACME_ISSUER)%'
            audience: '%env(APP_URL)%'
            keys: [acme]
            allowed_algorithms: [HS256]
        globex:
            issuer: '%env(GLOBEX_ISSUER)%'
            audience: '%env(APP_URL)%'
            keys: [globex]
            allowed_algorithms: [HS256]

    dispatchers:
        api:
            consumers: [acme, globex]
            realm: api
```

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            entry_point: medzuch_jwt.entry_point.api
            access_token:
                token_handler: medzuch_jwt.dispatcher.api
```

**The routing table is the consumers themselves.** Each already declares the `iss` it expects,
and that value is what a token is matched against — there is nowhere to write it twice and so
nowhere for two copies to disagree. It also means a per-tenant issuer can stay an environment
variable, which a key in a YAML map could not be.

### Why reading an unverified `iss` is safe

The dispatcher parses the token far enough to find `iss` and no further. Nothing is verified at
that point, and nothing needs to be: **choosing a judge grants nothing.** The consumer that name
selects then asks every question it would have asked anyway — the signature, its own `iss`, the
audience, the expiry, the profile — against its own keys.

So a caller who relabels a token to reach another tenant's consumer has bought the right to be
refused by that tenant's keys, which is the consumer they would have faced by sending the token
to that firewall directly. It is a switchboard, not a doorman.

**The allowlist is the listed consumers and nothing else.** An issuer none of them expects is
refused as `wrong_issuer` before a key is fetched, and so is a token whose issuer cannot be read
at all. There is no fallback consumer, and there will not be one: a fallback is where everything
unrecognised ends up, which is the opposite of what a tenant boundary is for.

### What belongs to the dispatcher, and what does not

The `WWW-Authenticate` realm is the dispatcher's, and so are `medzuch_jwt.entry_point.<name>` and
`medzuch_jwt.access_denied.<name>` under its name. A challenge goes out when there is no valid
token — before anything could say which tenant the caller meant — so it cannot belong to one of
the consumers behind it.

Everything else stays the consumer's. `JwtVerifiedEvent` names the tenant that accepted the
token, the log line is that consumer's, and a denylist is per consumer, as it was. The profiler
panel names the dispatcher, because it names whatever the firewall called; the `iss` among the
row's claims says which tenant took it from there.

A dispatcher's name cannot be a consumer's: both are things a firewall points at, and one name
cannot answer for two. The consumers arrive through a service locator, so a request builds the
one it routed to — a dispatcher in front of twenty tenants does not open twenty denylists to
answer one token.

### Encrypted tokens, and the one check the container cannot make

An encrypted token has no readable claims, so it routes on the `iss` its sender replicated into
the outer header (RFC 7519 §5.3) — which is exactly the case that section exists for, and what
`issuers.<name>.replicated_claims` writes. A JWE replicating nothing has no issuer here and is
refused; a tenant sending one has to be asked to replicate it.

Two consumers expecting the *same* issuer would make the route ambiguous, and that is not
refused when the container is built: an `issuer` is usually `%env(...)%` and has no value then.
The dispatcher asks it of itself when it is built instead, so `jwt:config:check` is where a
deploy finds out:

```
$ php bin/console jwt:config:check
 [FAIL] dispatcher "api": Dispatcher "api" cannot choose between consumers "acme" and "globex":
        both expect issuer "https://idp.example.com", and the token names one issuer.
```

Routing on anything other than the token — a host, a subdomain, a tenant header — is the
application's own handler, and a short one: `AccessTokenHandlerInterface` has a single method,
and the consumers are services you can inject by name.

## Reading an encrypted token

A signed token hides nothing. Anyone who holds one can read every claim in it — that is what
base64url is — and the signature only says nobody changed them. Where a token crosses something
you do not trust, a proxy you do not run or a queue somebody else can read, the claims go with
it: the subject, the scopes, and whatever else you put in.

An encrypted token is the same signed token inside a JWE (RFC 7519 §5.2 calls it a *nested*
JWT). The claims are ciphertext on the wire, and only a holder of the encryption key can see
them:

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

    jwe_keys:
        payload_2026:
            secret: '%env(base64:JWT_JWE_SECRET)%'
            algorithm: A256KW
            kid: 'enc-2026'

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
            jwe:
                keys: [payload_2026]
                allowed_key_management: [A256KW]
                allowed_content_encryption: [A256GCM]
```

Nothing else about the consumer changes. The firewall is wired the same way, the handler is the
same service, and the issuer, audience, expiry, scopes and profile of the token inside are
checked by exactly what checked them before — so an expired token in a perfect envelope is still
refused for being expired, with the same `RejectionReason` and the same 401. What the `jwe`
block adds is one step in front of all that: open the envelope, or refuse.

**A signed token on its own is then refused.** There is no "accept either" setting, and that is
deliberate: an attacker who could strip the outer layer and still be believed would have taken
the confidentiality away for the cost of deleting two segments. Moving an existing consumer onto
encryption means the senders go first — mint encrypted tokens, let the old ones expire, then add
the block.

### The two keys are two keys

`keys` sign and verify; `jwe_keys` encrypt and decrypt. They are separate sections because they
are separate keys: RFC 7517 §4.2 asks that one key serve one purpose, and the algorithms come
from different registries — `HS256` signs, `A256KW` wraps, and neither means anything to the
other.

A JWE key is a shared secret of an exact length, and `algorithm` says which:

| `algorithm` | What the key is | Bytes |
|---|---|---|
| `A128KW`, `A192KW`, `A256KW` | the key that wraps the one-time content key (RFC 7518 §4.4) | 16 / 24 / 32 |
| `A128GCMKW`, `A192GCMKW`, `A256GCMKW` | the same, wrapped with AES-GCM (§4.7) | 16 / 24 / 32 |
| `A128GCM`, `A192GCM`, `A256GCM` | the content key itself, for `dir` | 16 / 24 / 32 |
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | the same, for `dir`; doubled because it carries a MAC half (§5.2.2.1) | 32 / 48 / 64 |

The length is exact, not a floor, and it cannot be checked while the container is built — the
secret is still `%env(...)%` then. `jwt:config:check` builds every key, so that is where a
deploy finds out:

```
$ php bin/console jwt:config:check
 [FAIL] JWE key "payload_2026": Symmetric key for A256KW must be exactly 32 bytes (RFC 7518 §5); got 16
```

A secret is bytes rather than text, so `%env(base64:NAME)%` is the spelling that survives an
environment variable. `php -r 'echo base64_encode(random_bytes(32));'` produces one.

Every entry is checked, including one no consumer names yet — a key left behind after a rotation
fails the deploy gate rather than waiting to be noticed. Delete the entry when you delete the
secret.

### `dir`, and why it needs a `kid`

With `dir` there is no wrapping: the configured key *is* the content key, so it is bound to the
`enc` algorithm rather than to a wrapping one, and one token's claims are encrypted directly
under a key that never changes per token. It is the shortest configuration and the one with the
least room for error, at the cost of a key that many tokens share.

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%' }

    jwe_keys:
        payload_2026:
            secret: '%env(base64:JWT_JWE_SECRET)%'
            algorithm: A256GCM          # the content algorithm, because the key is the content key
            kid: 'enc-2026'

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
            jwe:
                keys: [payload_2026]
                allowed_key_management: [dir]
                allowed_content_encryption: [A256GCM]
```

The `kid` is required here rather than optional. A recipient picks a key by the `kid` in the
outer header, or failing that by the header's `alg` — and with `dir` that `alg` is the literal
string `dir`, which no key is bound to. A `dir` key without a `kid` would decrypt nothing, ever,
so the bundle refuses to boot with one.

### Rotating an encryption key

The same shape as rotating a signing key, and the same order: accept the new one first, then ask
the senders to use it.

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%' }

    jwe_keys:
        payload_2027: { secret: '%env(base64:JWT_JWE_SECRET_2027)%', algorithm: A256KW, kid: 'enc-2027' }
        payload_2026: { secret: '%env(base64:JWT_JWE_SECRET)%',      algorithm: A256KW, kid: 'enc-2026' }

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
            jwe:
                keys: [payload_2027, payload_2026]
                allowed_key_management: [A256KW]
                allowed_content_encryption: [A256GCM]
```

Both are tried by `kid`, so tokens sealed to either still open. Once nothing is sealed to the old
one — one token lifetime after the senders moved — drop it. Two keys with no `kid` between them
are refused at build for the reason a signing pair is: nothing could say which one a token meant.

### Repeating a claim in the outer header

RFC 7519 §5.3 lets a sender copy a claim into the outer header — `iss`, usually, so an
intermediary can route without holding a key — and requires the copy to agree with the token
inside. This consumer enforces that, and a disagreement is refused as `malformed`. The sending
half is `replicated_claims`, below.

**The comparison is exact.** An outer `"aud": "https://api.test"` beside an inner
`aud: ["https://api.test"]` is a disagreement here, because the producer chose the inner shape
and a receiver that normalised one side would be deciding that two different documents said the
same thing. JOSE peers do write the string form, so a sender replicating `aud` has to replicate
it as it stands.

A name in the outer header with no claim of that name inside is not compared at all: the section
is about a claim that was repeated, and a JWE protected header is also where a sender puts things
that were never claims. Registered JOSE header parameters — `alg`, `enc`, `kid`, `typ` and the
rest — are skipped whatever the token inside carries, so a claim of your own that happens to be
called `kid` is not measured against the `kid` that said which key to decrypt with.

### What the allowlists are for

`allowed_key_management` and `allowed_content_encryption` are what this consumer will accept in
the outer header, and everything else is refused before a key is touched. Every algorithm here
is authenticated encryption, so unlike a signing allowlist this one is not keeping a known-broken
scheme out; it is there because the header of an arriving token must never be what decides how
that token is read (RFC 8725 §3.1).

### What is not here yet

**Only shared secrets.** `ECDH-ES`, which encrypts to somebody's public EC key, needs a registry
of asymmetric encryption keys and a way to publish this application's own — a larger thing than a
name in a list. RSA key encryption is not coming: the library implements none, deliberately.

**Only the compact serialization.** The JSON serializations carry several recipients and
unprotected headers, which a bearer credential in an `Authorization` header has no use for.

**Write `cty` as `JWT` or `application/jwt`, not `application/JWT`.** The library compares media
types with the case kept after the prefix (medzuch/jwt-php#62), so the mixed-case long form is
refused as `malformed` until that is fixed. Nothing here works around it: a second implementation
of media-type comparison is a worse problem than the one it solves.

**Encrypted ID tokens and encrypted security events** are not configurable. `jwe` belongs to
`consumers` and to `issuers` — the section below is the issuing half — and the OIDC and SET
registrations sign and verify only.

## Minting an encrypted token

The other half: an issuer that signs and then encrypts what it signed (RFC 7519 §11.2 asks for
that order, and it is the only one the bundle can express). An application that is both ends
writes both blocks, and what comes out of one goes into the other:

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

    jwe_keys:
        payload_2026:
            secret: '%env(base64:JWT_JWE_SECRET)%'
            algorithm: A256KW
            kid: 'enc-2026'

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: default
            client_id: 'internal'
            audience: '%env(APP_URL)%'
            jwe:
                key: payload_2026
                key_management: A256KW
                content_encryption: A256GCM

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
            jwe:
                keys: [payload_2026]
                allowed_key_management: [A256KW]
                allowed_content_encryption: [A256GCM]
```

`$issuer->issue('alice')` now hands back a five-segment JWE instead of a three-segment JWS.
Nothing above that changed: the claims are the ones the four sources decided, `expiresIn` is the
lifetime the token was minted with, and `jti` names the token *inside* — which is what makes
revoking one still work, because that is the `jti` a consumer sees after opening the envelope.
The events fire as they did, on the claims rather than on the ciphertext.

**One of each, not a list.** A consumer takes `keys`, `allowed_key_management` and
`allowed_content_encryption` because a receiver has to accept everything its senders might still
be using. A sender picks one key and one algorithm of each kind and uses them. Rotation is that
asymmetry in practice: the receiving side's list grows first, and this side's `key` changes
afterwards.

The key has to be made of what the algorithm needs, and the container refuses to build otherwise
— `A256KW` with a key bound to `A192KW`, or `dir` with a key that is a content key for a
different `enc`. Encrypting with `dir` means the configured key *is* the content key:

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

    jwe_keys:
        content_2026:
            secret: '%env(base64:JWT_CEK)%'
            algorithm: A256GCM
            kid: 'enc-2026'

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: default
            client_id: 'internal'
            audience: '%env(APP_URL)%'
            jwe:
                key: content_2026
                key_management: dir
                content_encryption: A256GCM
```

### Replicating a claim for the intermediary

`replicated_claims` copies claims into the outer header, where something that holds no key can
read them — a gateway routing on `iss`, most often:

```yaml
medzuch_jwt:
    keys:
        default:
            hmac: '%env(JWT_SECRET)%'

    jwe_keys:
        payload_2026:
            secret: '%env(base64:JWT_JWE_SECRET)%'
            algorithm: A256KW
            kid: 'enc-2026'

    issuers:
        default:
            issuer: '%env(APP_URL)%'
            key: default
            client_id: 'internal'
            audience: '%env(APP_URL)%'
            jwe:
                key: payload_2026
                key_management: A256KW
                content_encryption: A256GCM
                replicated_claims: [iss]
```

The value written is read back out of the token that was just signed, so it is the claim exactly
— including its shape, which is the part that is easy to get wrong by hand. A receiver compares
the two and must reject a token where they disagree (§5.3), and this bundle's consumer does.

A claim the token does not carry is not written: §5.3 governs a claim that was *repeated*, and a
header member with nothing behind it would be an unauthenticated value nobody compares to
anything. A name that is a registered JOSE header parameter — `alg`, `kid`, `typ`, `cty` and the
rest — is refused at build, because in the outer header those mean something else entirely.

**Every replicated claim is a claim you decided not to encrypt.** That is the trade the section
exists for, and the reason the default is to replicate nothing.

## How old a token may be

`exp` is the issuer's decision about how long a token lives. `max_token_age` is yours about how
long you will accept one, counted from `iat`:

```yaml
medzuch_jwt:
    keys:
        default: { hmac: '%env(JWT_SECRET)%', algorithm: HS256 }

    consumers:
        api:
            issuer: '%env(APP_URL)%'
            audience: '%env(APP_URL)%'
            keys: [default]
            allowed_algorithms: [HS256]
            max_token_age: 300      # seconds since `iat`; off unless set
            leeway: 30
```

**It is a ceiling on somebody else's generosity.** An issuer you do not control minting
twenty-four-hour tokens is a token that keeps working for a day after it leaks. Set this and it
stops working when your ceiling runs out instead, without any conversation with the issuer and
without touching what they mint.

A token refused this way is **`too_old`, not `expired`**, on the event and in the profiler. They
are different facts about different clocks — one is the issuer's lifetime running out, the other
is this application refusing a lifetime the issuer thought reasonable — and an operator watching
the two together would read a policy of theirs as an incident.

`leeway` widens it, exactly as it widens `exp`, `nbf` and `iat`: the age is computed across two
clocks and inherits the skew between them. Above, a token is accepted at five minutes and thirty
seconds old and refused once it is older than that. The comparison is in whole seconds, because
`iat` is one (RFC 7519 NumericDate) and a boundary that depended on the microseconds of whichever
clock asked would not be a boundary.

**This is a consumer's option, and ID-token registrations do not have it.** An `IdTokenVerifier`
is called where a provider hands you a token, not on a firewall, and OIDC's own freshness question
is a different one — `max_age` and `auth_time` are about how long ago the *user* authenticated,
which is the provider's answer to give rather than a ceiling you impose on their token.

**A token with no `iat` is refused rather than exempted.** RFC 9068 §2.2 requires it and the
profile enforces it, so this cannot happen through the access-token path — but reading "no
issuing time" as "young enough" would exempt exactly the tokens whose age cannot be checked.

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

## Publishing your own metadata

A relying party that knows your issuer identifier and nothing else finds the rest in a metadata
document (RFC 8414). It is the other side of
[discovering an issuer's keys](#discovering-an-issuers-keys): what that section reads from
somebody else, this one publishes about you.

```yaml
medzuch_jwt:
    metadata:
        issuer: '%env(APP_URL)%'
        jwks_uri: '%env(APP_URL)%/.well-known/jwks.json'
        extra:
            response_types_supported: ['code']
            token_endpoint: '%env(APP_URL)%/oauth/token'
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'private_key_jwt']
```

```yaml
# config/routes.yaml
medzuch_jwt_metadata:
    path: /.well-known/oauth-authorization-server
    methods: [GET]
    controller: medzuch_jwt.metadata_controller
```

**Two members are the bundle's; the rest is yours.** `issuer` and `jwks_uri` are the only things
a JWT bundle knows about your deployment, and they are filled in from the options above.
Everything else a metadata document carries — the endpoints, the grant types, the response types
— describes an authorization server, and [running one is a permanent non-goal](#what-it-deliberately-does-not-do).
So `extra` is handed through verbatim, and naming `issuer` or `jwks_uri` in it is refused: two
spellings of one member could disagree, and JSON may only answer once.

**A document without `response_types_supported` is refused at container build.** RFC 8414 §2
requires it, this bundle cannot supply it, and serving a document that claims conformance it
does not have is worse than refusing to start. If you are not an authorization server at all —
you verify tokens somebody else mints — then you have no metadata to publish, and omitting the
section is the right answer rather than filling it with plausible values.

**Both identifiers are HTTPS-only, and the issuer may carry no query or fragment** (RFC 8414 §2).
A document fetched over a channel an attacker can rewrite names whatever keys and endpoints they
like, and an identifier with a query string is one no reader can compare against the identifier
it asked for. Both rules are checked twice: when the container is built, for a value written
literally, and when the service is first built, which is the only moment a `%env(APP_URL)%` has
a value at all. `jwt:config:check` builds it, so a deploy with a plaintext `APP_URL` is a red
line in the gate rather than a 200 nobody should have trusted.

**The route has to be reachable without a token**, exactly as the JWK Set's does — a reader who
has to authenticate to find out where the keys are is a reader who cannot get started:

```yaml
security:
    access_control:
        - { path: ^/\.well-known/oauth-authorization-server$, roles: PUBLIC_ACCESS }
        - { path: ^/, roles: IS_AUTHENTICATED_FULLY }
```

The exemption goes before the catch-all; reversed, the rule above it never matches. The response
carries an `ETag` over the document, so `cache_max_age: 0` means revalidate rather than refetch.

**One controller, either well-known path.** RFC 8414 serves at
`/.well-known/oauth-authorization-server` and OIDC Discovery at
`/.well-known/openid-configuration`; the two differ in what the document carries, not in how it
is served, so route the same controller wherever your readers look — and put what that spelling
needs in `extra`. OIDC Discovery additionally requires `authorization_endpoint`,
`subject_types_supported` and `id_token_signing_alg_values_supported`; this bundle knows none of
the three, so an OIDC document needs them named there.

**Two things the paths do not share.** An issuer identifier *with a path* — a Keycloak realm,
say — is read at `identifier + /.well-known/openid-configuration` by OIDC Discovery, while
RFC 8414 inserts its suffix *before* the path component. The two stop agreeing exactly when the
identifier has a realm in it, so route both if your readers are mixed. And a browser-based
relying party reading this endpoint needs CORS, which is your application's to configure: this
bundle sets no CORS header here, the same as on the JWK Set.

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

### Discovering an issuer's keys

An identity provider that publishes OIDC metadata already says where its keys are. Name the
issuer instead of the endpoint and the `jwks_uri` is read from
`/.well-known/openid-configuration`:

```yaml
medzuch_jwt:
    remote_jwks:
        partner_idp:
            discovery: 'https://idp.example.com'

    consumers:
        partner:
            issuer: 'https://idp.example.com'
            audience: '%env(APP_URL)%'
            remote_jwks: partner_idp
            allowed_algorithms: [RS256]
```

`uri` and `discovery` are alternatives; a set naming both, or neither, is refused when the
container is built. Everything else is unchanged — the same client, the same cache, the same
`cache_ttl`, `min_refresh` and `max_body_bytes` — and the metadata document is cached under the
same lifetime as the key set, so the common path still touches no network.

What it buys is the endpoint moving without a deploy. What it costs is one more hop to trust,
which is why two things are checked before it is:

- **The document has to name the issuer back.** OIDC Discovery §4.3 requires the `issuer` it
  states to be the identifier it was fetched for, and this bundle refuses the document when it
  is not. Without that check, whoever answers the well-known path chooses which keys this
  application trusts. One trailing slash is tolerated — providers are inconsistent about
  publishing it — and nothing else is.
- **Both hops are HTTPS.** A plaintext `discovery` is refused when the container is built, and
  a `%env(...)%` one — which cannot be read then — when the resolver is first built, before any
  request leaves. A `jwks_uri` that comes back plaintext is refused when it arrives, because
  that one is the issuer's to choose and no configuration can settle it in advance.

A discovery failure is the same kind of failure a `jwks_uri` fetch failure is, so local keys
still cover an outage — including an outage of the metadata endpoint itself.

Three things this does not check, and one of them is yours:

- **Redirects belong to the HTTP client.** Symfony's follows them by default. A cross-origin
  redirect changes which host answered the well-known path, and the issuer echo cannot see the
  difference — the host that redirected you can state the identifier you asked for. Configure
  the client used for `remote_jwks` not to follow redirects off the issuer's origin.
- **A consumer's `issuer` and its set's `discovery` are not required to agree.** Keys hosted
  off the issuer are a real setup, so this is not refused — but the two being different is more
  often a typo than a deployment, and it compiles either way.
- **A long-lived worker keeps the endpoint it already discovered.** Under PHP-FPM the answer
  lasts one request. Under FrankenPHP worker mode, RoadRunner or Swoole the resolver outlives
  `cache_ttl`, so a moved endpoint is picked up when the worker is recycled.

An issuer identifier with a path is read at the OIDC Discovery spelling — identifier, then
`/.well-known/openid-configuration` — which is what Keycloak and Azure AD publish. RFC 8414
inserts the suffix before the path instead; a provider that has a path publishes both.

Use `discovery` when the provider may move the endpoint, and `uri` when they may not: one
fewer request, and one fewer thing that can be wrong, for a URL that was never going to change.

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

## Sending and receiving security events

A Security Event Token (RFC 8417) says that something happened to somebody — an account was
disabled, a credential was compromised, a session was revoked. It is what RISC and CAEP are
built on, and it travels between an identity provider and the applications that trust it,
outside any login.

**A SET is not a credential.** It arrives in the body of a POST to a delivery endpoint, describes
a subject who is not the caller, and grants nothing. There is no firewall to wire it into, so
both halves are services your code calls, like the ID-token verifier and for the same reason.

### Receiving

```yaml
medzuch_jwt:
    remote_jwks:
        partner_idp:
            uri: 'https://idp.example.com/.well-known/jwks.json'

    security_events:
        consumers:
            risc:
                issuer: 'https://idp.example.com'
                remote_jwks: partner_idp
                allowed_algorithms: [RS256]
                audience: '%env(APP_URL)%'
```

```php
use Medzuch\Jwt\Exception\JwtException;
use Medzuch\JwtBundle\SecurityEvent\SecurityEventVerifier;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class ReceiveSecurityEvents
{
    // `$events` and the `$seen` store further down are yours: this bundle
    // verifies the token and stops there.
    public function __construct(
        private readonly SecurityEventVerifier $risc,
        private readonly HandlesSecurityEvents $events,
    ) {}

    public function __invoke(Request $request): Response
    {
        try {
            $claims = $this->risc->verify($request->getContent());
        } catch (JwtException) {
            // RFC 8935 §2.3: the delivery failed, and the transmitter should
            // hear so rather than be told the event was accepted.
            return new Response(status: Response::HTTP_BAD_REQUEST);
        }

        foreach ((array) $claims->get('events') as $type => $payload) {
            $this->events->handle($claims->subject(), $type, $payload);
        }

        return new Response(status: Response::HTTP_ACCEPTED);
    }
}
```

The verifier is injectable by the name you configured it under — `SecurityEventVerifier $risc`
above — so an application receiving from two transmitters names each rather than looking one up
by string. Checked: signature and algorithm, `iss`, `aud` when you configure one, the
`secevent+jwt` type, the claims §2.2 requires, and that `events` is a non-empty JSON object.

**A SET has no expiry, and that is a decision you inherit.** RFC 8417 §4.1.4 makes `exp`
meaningless for an event — it describes the past, so there is no moment it stops being true —
which means a replayed delivery verifies exactly like the first one, forever. **Deduplicate on
`jti`**, which every SET is required to carry:

```php
if (!$this->seen->add($claims->jwtId())) {
    return new Response(status: Response::HTTP_ACCEPTED); // already handled
}
```

The bundle does not do this for you, and the denylist it ships is not the seam for it: `revoke()`
takes the moment an entry may be forgotten, which for an access token is its `exp` and for a SET
is nothing at all. Store the `jti` for as long as your transmitter might retry — their delivery
policy decides it, not this bundle.

### Transmitting

```yaml
medzuch_jwt:
    keys:
        risc_signing: { pem_private: '%kernel.project_dir%/config/jwt/risc.pem', algorithm: RS256, kid: 'risc-2026' }

    security_events:
        issuers:
            risc:
                issuer: '%env(APP_URL)%'
                key: risc_signing
                audience: 'https://rp.example.com'
```

```php
use Medzuch\JwtBundle\SecurityEvent\SecurityEventIssuer;

final class AnnouncesDisabledAccounts
{
    public function __construct(private readonly SecurityEventIssuer $risc) {}

    public function announce(string $userId, string $reason): string
    {
        return (string) $this->risc->issue()
            ->subject($userId)
            ->event('https://schemas.openid.net/secevent/risc/event-type/account-disabled', [
                'reason' => $reason,
            ])
            ->build();
    }
}
```

`issue()` hands back the library's builder rather than taking arguments, because what varies
between two events is the events themselves and no argument list would say that better. The
stream supplies `iss`, `iat`, a random `jti`, the `secevent+jwt` type and the configured
`audience`; you declare at least one event — a SET without one is refused when you build it —
and anything else RFC 8417 allows, including `toe` for when the event happened and `txn` to
correlate it with other messages.

**There is no `ttl`.** Not an omission: §4.1.4 again, and the library's builder has no setter
for `exp` either. If you want a receiver to ignore stale events, send `toe` and let them decide;
an expiry would be this application claiming an event stops having happened.

Delivering the token is yours — push over HTTPS (RFC 8935) or a poll endpoint (RFC 8936) —
along with retries. The bundle mints and verifies; it does not own your transport.

## From the console

Five commands, and none of them a second implementation of anything: each asks the services your
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

`--consumer` names an **access-token** consumer. An ID token or a security event token still
decodes — that half needs no configuration — but a consumer asked to verify one refuses it as
`malformed`, because `typ` says it is not the kind of token that consumer reads. Those are
verified by `IdTokenVerifier` from your callback and by `SecurityEventVerifier` from your
delivery endpoint, not by a firewall (DEC-8).

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

`jwt:config:check` builds everything the container left for later and says what broke:

```bash
bin/console jwt:config:check              # 0 when everything answered, 1 when anything did not
bin/console jwt:config:check --skip-remote
```

The container refuses the mistakes it can see when it is built. This is for the ones it cannot:
a `pem_private` naming a file that was not deployed, an env variable that arrived empty, a secret
two bytes shorter than its algorithm allows, an issuer whose JWK Set cannot be reached *from
here*. All of those are factory arguments, and a factory runs when its service is first used —
which is to say, on somebody's first request. Run this as a deploy step and the deploy fails
instead.

Exit status: `0` everything answered, `1` something did not, `2` there was nothing configured to
check — because `jwt:config:check && deploy` going green on an application whose package file
never arrived is the one way this command could mislead.

Remote sets are fetched, so `--skip-remote` is there for a gate with no network; what it does not
check, it says it did not check rather than passing quietly. A reached set is reported as
reachable and not as *useful*: the probe asks for a key id nobody published, and an empty
document misses it exactly as a full one does.

**`ok` means built**, which is worth reading literally. Building a consumer builds its denylist —
but a denylist's constructor stores a cache adapter and asks it nothing, so a Redis that will
fail on the first request looks fine here. Building an issuer builds every claim provider behind
it, which is the point: a provider that cannot be constructed fails the deploy, and one that
opens a connection in its constructor opens it here.

`jwt:key:generate` is the fifth — see [Generating keys](#generating-keys).

**A minted token is a working credential** for as long as it lives. It is on your screen and in
your shell history; `--raw` at least keeps the surrounding text out of a log.


## The profiler panel

Where a profiler is enabled, every token a consumer was shown appears in a **JWT** panel: which
consumer decided, whether it was accepted or refused, **why** it was refused, the algorithm and
key id the token named, and how long verifying took.

The reason is the point. A refusal tells the caller `invalid_token` and nothing else, deliberately
— and then you have to work out which of expired, wrong audience, unknown key or revoked it was.
The panel is where that question is safe to answer, because nobody but you is reading it.

Nothing is configured: the collector is registered where a `profiler` service is and removed
where it is not, and the handler your firewall calls is wrapped only in the first case — a
decorator recording into nothing has no business on the hot path of every authenticated request.
It follows the profiler rather than the environment, so a staging deployment with the profiler on
is traced too.

Three things the panel does not show, each for the same reason — it reports what a **consumer**
decided, not how the request ended:

- **`accepted` is the consumer's verdict, not the firewall's.** In `user.mode: provider` and
  `claims`, Symfony loads the user after the handler returns, so a token can be accepted here and
  the request still end in `401` because your store has no such user. "Would authenticate as" is
  the exact phrase.
- **Only handlers a firewall calls are traced.** `medzuch_jwt.handler.<name>` injected somewhere
  of your own, or `jwt:token:inspect`, verifies without a panel row.
- **ID tokens and security events are not consumers.** `IdTokenVerifier` and
  `SecurityEventVerifier` are services your own code calls (DEC-8); nothing about either reaches
  here.

**The token itself is never collected.** Profiler data is written to disk and served back by a
URL, so a bearer token in there is a credential in a file — and one a screenshot in a bug report
would carry out of the building. The panel shows the claims instead, as the token has them:
unverified, which is exactly what a refused token leaves you to read.

The claims *are* stored, though, and a token's claims are usually about a person. The panel's
privacy is the profiler's — the same directory, the same `/_profiler` URL, the same care about
who can reach either. That is the trade this panel makes deliberately: a panel that hid what the
token said could not answer the question it exists for.


## Testing an application that uses this

Two things ship in `src/Test/` for your own functional suite.

**`TestTokenFactory`** mints the tokens your firewall has to refuse, which the issuer will not
make for you — it mints tokens meant to work:

```php
use Medzuch\JwtBundle\Test\TestTokenFactory;

$tokens = TestTokenFactory::hmac('https://issuer.test', 'https://api.test', $secret);

$tokens->token('alice', scopes: ['reports.read']);   // accepted
$tokens->expired();                                  // exp an hour ago
$tokens->notYetValid();                              // nbf an hour out
$tokens->withAudience('https://other.test')->token();
$tokens->withIssuer('https://elsewhere.test')->token();
```

For RS256, ES256 or EdDSA, hand it the private key your issuer signs with:

```php
$key = RsaPrivateKey::fromPem(file_get_contents('config/jwt/default.private.pem'), 'RS256');

$tokens = TestTokenFactory::signedWith('https://issuer.test', 'https://api.test', new Rs256(), $key);
```

A token signed by somebody else is a second factory rather than a method — every algorithm gets
the same answer and there is nothing to switch on:

```php
$stranger = TestTokenFactory::hmac('https://issuer.test', 'https://api.test', 'another-secret-of-32-bytes-plus!!');
```

For a consumer that reads encrypted tokens, seal what the factory mints — otherwise a firewall
configured that way refuses everything the factory makes, for being unencrypted:

```php
use Medzuch\Jwt\Algorithm\Encryption\A256Gcm;
use Medzuch\Jwt\Algorithm\KeyManagement\A256Kw;
use Medzuch\Jwt\Key\OctKey;

$tokens = TestTokenFactory::hmac('https://issuer.test', 'https://api.test', $secret)
    ->encryptedWith(new A256Kw(), new A256Gcm(), OctKey::fromBinary($sealing, 'A256KW', 'enc-2026'));
```

The refusals are sealed too, which is the point of putting it on the factory: `expired()` still
returns a token that opens and is then refused for its expiry, rather than one refused at the
envelope for the wrong reason. The algorithm and the key are given as objects rather than names
because they are one decision — a `dir` recipient's key is bound to the content algorithm while a
wrapping one is bound to the key-management algorithm, and a pair of strings could not say which.

**It reads no configuration, deliberately.** A test that mints from the same container it
verifies against cannot catch a configuration mistake: an `audience` wrong in both halves agrees
with itself and the test passes. Naming the issuer, the audience and the key in the test is what
makes it an assertion about the contract.

**`AssertsBearerChallenges`** says what a refusal should have carried, without asserting the
whole header — which breaks the day your realm changes:

```php
use Medzuch\JwtBundle\Test\AssertsBearerChallenges;

final class ApiTest extends WebTestCase
{
    use AssertsBearerChallenges;

    public function testRefusals(): void
    {
        $client = static::createClient();

        $client->request('GET', '/api/reports');
        self::assertBearerChallenge($client->getResponse(), realm: 'api');   // and no error, per RFC 6750 §3

        $client->request('GET', '/api/reports', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokens->expired()]);
        self::assertInvalidToken($client->getResponse());

        $client->request('GET', '/api/reports', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokens->token('alice')]);
        self::assertInsufficientScope($client->getResponse(), 'reports.read');

        // A role, an expression, a voter of your own: this bundle says nothing.
        self::assertNoBearerChallenge($client->getResponse());
    }
}
```

**Time travel** is one configuration line, in `config/packages/test/`:

```yaml
services:
    test.frozen_clock:
        class: Medzuch\Jwt\Primitives\FrozenClock
        factory: [Medzuch\Jwt\Primitives\FrozenClock, at]
        arguments: ['2026-01-01T00:00:00+00:00']
        public: true

medzuch_jwt:
    clock: test.frozen_clock
```

Every consumer, issuer and denylist reads that clock, so one tick expires a token without
anything sleeping:

```php
$clock = self::getContainer()->get('test.frozen_clock');
$token = $tokens->withClock($clock)->token('alice');   // the same clock, or `iat` comes from
                                                       // one and `exp` is checked against another

$clock->tick(new DateInterval('PT2H'));                // the same request now gets a 401
```


## Configuration reference

The complete tree, with every option, default and explanation, is generated from the bundle
itself:

```bash
bin/console config:dump-reference medzuch_jwt
```

That output is always accurate for the version you have installed, which a hand-written
reference in this file would not be. A copy of it ships with the package as
[`docs/configuration-reference.md`](docs/configuration-reference.md), for reading without a
console; the suite holds the two together.

## Mistakes it refuses to boot with

Configuration errors fail when the container is built, naming the key at fault, rather than
looking like rejected tokens at runtime:

- a consumer or issuer naming a key that does not exist
- a dispatcher routing to a consumer that does not exist, naming one twice, or taking the name of
  a configured consumer — both are handlers a firewall points at, and one id cannot be two
- an allowed algorithm with no key behind it — a token using it could never be verified
- two keys in one consumer's set that a token cannot tell apart: sharing a `kid`, or sharing an
  algorithm with no `kid`
- a key given the wrong kind of material for its algorithm — a secret for `RS256`, a PEM for
  `HS256` or for `EdDSA`, more than one kind at once, or none
- a consumer verifying with a private-only key, or an issuer signing with a public-only one —
  a security-event stream is held to the same rule, and named as a stream when it breaks it
- a security-event consumer with nothing to verify with: no `keys` and no `remote_jwks`
- a consumer that could never open an encrypted token: a `jwe_keys` name that does not exist, an
  allowed `alg` no configured key can be used with, a key bound to something the consumer does
  not allow, two keys a token cannot tell apart, or a `dir` key with no `kid` — which no
  recipient could ever select
- an issuer that could never seal one: a `jwe_keys` name that does not exist, or a key that is
  not made of what the algorithm it names needs — a key that wraps with `A256KW` cannot wrap
  with `A192KW`, and a `dir` key is a content key for one `enc` and no other
- a `replicated_claims` entry named after a registered JOSE header parameter — in the outer
  header `alg`, `kid`, `typ` and `cty` mean something else, and a receiver skips them rather
  than comparing them to a claim
- a JWK Set publishing a shared secret, a key with no public half, or a key that does not exist
- a static claim named `iss`, `sub`, `aud`, `exp`, `nbf`, `iat` or `jti` — those are set from
  configuration or by the profile
- a YAML map where a sequence is expected, an unknown algorithm name, leeway above the
  library's ceiling
- a `token_type` that names a type the library has a profile for, carries the `application/`
  prefix RFC 7515 §4.1.9 leaves off the wire, or is padded with whitespace — three spellings
  that each verify something other than what they look like
- a consumer that lists `required_claims` without a `token_type`, requires claims that do not
  include `exp` and sets no `max_token_age` — a token nothing can make stale — or has a denylist
  and does not require `jti`, which is what a denylist looks a token up by
- a remote key set naming both a `uri` and a `discovery` issuer, or neither, or one of them
  blank or over plaintext — a plaintext value that arrives from `%env(...)%` is refused when
  the resolver is built instead, since there is nothing to read at build
- a `log_levels` entry that is not one of the eight PSR-3 levels, or any level at all with no
  `logger` to emit at it
- a service this application does not have: `clock`, `logger`, a remote set's `http_client`,
  `request_factory`, `cache` or `cache_pool`, a consumer's `denylist.service`,
  `denylist.cache`, `denylist.cache_pool` or `user.factory`. The message names the
  configuration key rather than the service id behind it, and says when the id is a default
  you never wrote — `psr18.http_client` without `framework.http_client` enabled, or `cache.app`
  without a cache

A JWK is read when the key is first built rather than when the container is compiled — the
document stays a path or an environment reference so it never lands in the compiled container —
so what it says is checked there: a document disagreeing with the configuration about `alg` or
`kid`, a private JWK where the public half belongs, or a JWK Set where a key does.

## What it deliberately does not do

Refresh-token storage and rotation, user entities and login forms, OAuth 2.0 authorization-server
machinery (consent, grants, PKCE), and session-based authentication are all outside this package.
Section 8 of [`docs/plan.md`](docs/plan.md) explains why for each.

## Documentation

This file is the reference: every feature, one at a time, with what it costs and what it does
not do. The rest:

- [`docs/cookbook.md`](docs/cookbook.md) — recipes that assemble those features into a task an
  application has: machine tokens between services, two issuers on one API, tenants, a browser
  SPA on a cookie, gating a deploy.
- [`UPGRADE.md`](UPGRADE.md) — what each release asks of an application already running the
  previous one.
- [`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md) — what counts as public API from 1.0,
  and how anything in it is allowed to change.
- [`docs/plan.md`](docs/plan.md) — the design, the feature catalogue with priority tiers, the
  recorded decisions, and the roadmap.
- [`CHANGELOG.md`](CHANGELOG.md) — what has landed so far.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to work on it.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability. Not through a public issue.

Every `medzuch_jwt` example in this file and in the cookbook is compiled into a real container by
the test suite, and every service id they name has to be one an example builds — so a renamed
key cannot leave the documentation describing a bundle that no longer exists.

## License

MIT — see [LICENSE](LICENSE).
