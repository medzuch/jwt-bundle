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
