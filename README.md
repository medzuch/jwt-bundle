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

> **Status: pre-1.0.** The MVP works end to end — issue a token on login, verify it on a
> firewall, be authenticated — with HMAC, RSA and EC keys, key rotation and a JWKS endpoint.
> Nothing about it is stable yet; see [`docs/plan.md`](docs/plan.md) for the full design and
> roadmap.

Requires PHP 8.3 / 8.4 and Symfony 6.4 LTS, 7.4 LTS or 8.x.

## Installation

The package is not on Packagist yet and has no tagged release, so point Composer at the
repository and ask for the development branch by name — a plain `composer require` finds no
stable version to install.

Add the repository to your `composer.json`:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/medzuch/jwt-bundle" }
    ]
}
```

Then:

```bash
composer require medzuch/jwt-bundle:dev-develop
```

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
given: a shared secret for `HS*`, a PEM for `RS*` and `ES*`.

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

Generate a keypair with:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out config/jwt/private.pem
openssl pkey -in config/jwt/private.pem -pubout -out config/jwt/public.pem
```

A resource server verifying someone else's tokens configures only the public half. An
authorization server that does not verify its own tokens configures only the private one.

`EdDSA` is listed as an algorithm but has no key source yet: Ed25519 has no PEM representation
in the library, and a JWK source is planned. Configuring it says so rather than failing
obscurely.

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

## Rotating a key

Rotation is a configuration move rather than a feature. An issuer signs with **one** key while a
consumer accepts **several**, so a new key can start signing while tokens from the old one are
still in flight:

1. Add the new keypair alongside the old one, each with its own `kid`.
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
  `HS256`, both at once, or neither
- a consumer verifying with a private-only key, or an issuer signing with a public-only one
- a JWK Set publishing a shared secret, a key with no public half, or a key that does not exist
- a static claim named `iss`, `sub`, `aud`, `exp`, `nbf`, `iat` or `jti` — those are set from
  configuration or by the profile
- a YAML map where a sequence is expected, an unknown algorithm name, leeway above the
  library's ceiling

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
