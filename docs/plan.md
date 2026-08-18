# medzuch/jwt-bundle — Design Plan (v0.4)

> **Goal.** A Symfony bundle that wires the standalone `medzuch/jwt-php` library
> into a Symfony application, so an app can **issue** and **verify** JOSE tokens
> (RFC 9068 access tokens, OIDC ID tokens, RFC 8417 security event tokens,
> custom JWS/JWE) through Symfony's native Security stack, DI, config, console
> and profiler — without writing crypto or claim-validation glue by hand.
>
> **Audience.** Any Symfony 6.4/7.x application, in any of these roles:
> resource server (verify bearer tokens), authorization server (mint tokens on
> login), OIDC relying party (verify a third-party IdP's tokens via JWKS),
> service-to-service caller, or all of the above in one process.
>
> **Status.** Design only — no bundle code exists yet (Phase 0 in §7).
>
> **v0.4 change.** The plan is now written for the package itself rather than
> for one consuming application. Everything previously scoped, trimmed or
> dropped "because the first consumer doesn't need it" has been reinstated as a
> planned, *opt-in* capability with an explicit tier (§3, §8). The MVP is still
> small — what changed is that the small MVP is now a deliberate first slice of
> a general design, not the whole design.

---

## 0. Guiding principles

1. **Thin adapter, not a re-implementation.** All crypto, parsing, claim
   validation and RFC conformance stays in `medzuch/jwt-php`. The bundle does
   DI wiring, configuration, Symfony contracts, console/profiler integration —
   nothing that could live in the library instead. If a feature needs new
   crypto or claim logic, it belongs upstream in the library.
2. **Native integration first.** Prefer Symfony's built-in `access_token`
   authenticator + `AccessTokenHandlerInterface` over a bespoke authenticator.
   Write a custom authenticator only where the native one cannot express
   something (e.g. DPoP proof binding, §3.6).
3. **Secure-by-default, complexity opt-in.** Defaults are the strict ones:
   stateless firewall, explicit algorithm allowlist (no `alg` confusion), `typ`
   pinning, required-claim enforcement, zero clock leeway, no `jku`/`x5u`
   following. Every feature beyond the MVP is off unless configured; nothing
   dangerous is reachable by omission.
4. **No single-application assumptions.** The bundle must not hard-code one
   app's identity model, authorization model, key layout, or login flow. Where
   an app-specific policy is needed, the bundle ships an **interface + a safe
   default implementation** and lets the app replace it (`#[AsAlias]`,
   `#[AutoconfigureTag]`, or config).
5. **Multiplicity is the normal case.** Multiple firewalls, multiple token
   kinds, multiple issuers, multiple keys. The config tree is *named
   collections* from day one (§4), even when the first release only exercises
   the `default` entry — retrofitting names later is a BC break.
6. **Target versions.** PHP 8.3+ (matches the library), Symfony 6.4 LTS and
   7.x. `symfony/security-bundle` is a hard requirement; HTTP client, cache,
   Doctrine, Monolog are all optional integrations.
7. **Public package discipline.** Semantic versioning, a BC policy, `@internal`
   markers on everything not meant to be extended, upgrade notes, and the same
   QA gates as the library (php-cs-fixer, PHPStan level 9, PHPUnit, mutation
   testing on the security-critical paths).

---

## 1. Background — what a modern Symfony bundle looks like

A bundle is reusable code (services, config, contracts) packaged for many
Symfony apps. In Symfony 6.4/7.x the recommended base is `AbstractBundle`,
which collapses the old `Bundle` + `Extension` + `Configuration` trio into one
class.

**Planned anatomy:**

```
jwt-bundle/
├── composer.json                  # type: symfony-bundle, requires medzuch/jwt-php
├── src/
│   ├── MedzuchJwtBundle.php       # AbstractBundle: configure() + loadExtension()
│   ├── DependencyInjection/       # config tree, compiler passes, per-firewall factories
│   ├── Security/                  # token handlers, user resolution, voters, denylist
│   ├── Issuer/                    # token-minting services, claim providers
│   ├── Key/                       # key source loaders, key registry, rotation
│   ├── Jwks/                      # JWKS publisher controller + remote JWKS wiring
│   ├── Event/                     # dispatched events
│   ├── Command/                   # console commands
│   ├── DataCollector/             # profiler panel
│   └── Test/                      # test helpers shipped to consumers
├── config/
│   ├── services.php               # service definitions
│   └── routes.php                 # optional routes (JWKS, discovery)
└── tests/                         # unit + functional (real test kernel)
```

Key mechanics that shape the design:

- **Registration.** `Medzuch\JwtBundle\MedzuchJwtBundle::class => ['all' => true]`
  in `config/bundles.php`, or automatically via a Flex recipe (§3.5).
- **`AbstractBundle::configure()`** defines the config tree; **`loadExtension()`**
  reads the validated config and registers/parameterizes services.
- **Config root key** `medzuch_jwt`; namespace `Medzuch\JwtBundle\`; composer
  name `medzuch/jwt-bundle`.
- **Bundle-internal service config** in PHP (`config/services.php`) for
  type-safety; the **app-facing** config is YAML (`config/packages/medzuch_jwt.yaml`),
  matching how apps configure every other bundle.
- **Firewall integration** may additionally need a `AuthenticatorFactoryInterface`
  (security bundle extension point) if we ship our own firewall key
  (`medzuch_jwt: ~` under a firewall) as a shorthand over the native
  `access_token` block — see §3.1.

---

## 2. Background — Symfony Security, and where JWT plugs in

```
Request
  → Firewall (pattern match; stateless for APIs)
    → Authenticator ("who are you?")
      → Passport (UserBadge + badges)
        → User Provider (loads/refreshes the user)
          → CheckPassportEvent (extra validation)
            → Authorization (access_control / #[IsGranted] / Voters)
              → Controller
```

### 2.1 The native fit: `access_token` + `AccessTokenHandlerInterface`

Symfony ships an `AccessTokenAuthenticator` for stateless bearer auth. The app
configures it and supplies a **token handler**:

```yaml
security:
  firewalls:
    api:
      pattern: ^/api
      stateless: true
      access_token:
        token_handler: medzuch_jwt.handler.api      # our service
        token_extractors: [header]                  # native; see §3.1
```

The handler implements one method:

```php
interface AccessTokenHandlerInterface
{
    public function getUserBadgeFrom(string $accessToken): UserBadge;
}
```

**This is the primary integration point.** Our handler:

1. Takes the raw compact token string.
2. Validates it through the configured library consumer
   (`AccessTokenProfile::consumer(...)->parse($token)`) → a validated
   `ClaimsSet`, or a thrown `JwtException`.
3. Applies post-validation policy the library does not own: denylist / `jti`
   revocation check, max token age, sender-constraint check (§3.6).
4. Builds a `UserBadge` from the configured identity claim, with an optional
   user loader that turns claims into a user object without a DB round-trip.
5. On failure throws `BadCredentialsException` (Symfony maps it to 401), while
   the original library exception is logged, not leaked to the client.

### 2.2 Turning a token into a `User` — three supported strategies

Different applications answer this differently, so this is configuration, not a
hard-coded choice:

| Mode | What the handler returns | When to use |
|---|---|---|
| `provider` (default) | `UserBadge($claims->get($identityClaim))` — the app's own user provider loads the entity | Tokens carry identity only; authorization reads current state from the DB (no stale-privilege risk) |
| `claims` | `UserBadge($id, fn () => new JwtUser($claims, $roles))` — a bundle-provided `UserInterface` built purely from claims | Stateless services with no user table; third-party tokens whose subjects don't exist locally |
| `custom` | Delegates to an app service implementing `UserFromClaimsInterface` | Hybrid: DB lookup with claim-derived fallback, tenant resolution, JIT provisioning |

Role derivation is likewise opt-in: a `ClaimRoleMapper` can map `scope`,
`roles`, `groups` or any claim to Symfony roles with a configurable prefix, and
is simply absent when the app authorizes from the database instead.

---

## 3. Feature catalogue — what such a bundle can and should provide

Tiers: **T1** = MVP (Phase 1), **T2** = should exist before a 1.0 (Phases 2–4),
**T3** = when a concrete need appears (Phase 5+). Every T2/T3 item is off by
default and adds no runtime cost when unconfigured.

### 3.1 Consumer side — verifying incoming tokens

| # | Capability | Backed by | Tier |
|---|---|---|---|
| C1 | `AccessTokenHandler` implementing `AccessTokenHandlerInterface`, one instance per named consumer | `AccessTokenProfile::consumer()` | T1 |
| C2 | Named consumers bindable to different firewalls (public API vs. admin vs. internal) | DI, config tree §4 | T1 |
| C3 | User resolution modes `provider` / `claims` / `custom` (§2.2) incl. a `JwtUser` value object | `ClaimsSet` | T1 (`provider`), T2 (rest) |
| C4 | Claim → role mapping (`scope`, `roles`, `groups`, custom), configurable prefix and separator | `ClaimsSet::getList()/getString()` | T2 |
| C5 | Token extractors: `header` (Bearer), `query`, `cookie`, `body`, custom service — cookie matters for browser SPAs | Native Symfony extractors + ours | T2 |
| C6 | ID-token handler for OIDC relying-party flows (`nonce`, `azp`, `at_hash` checks) | `IdTokenProfile::consumer()` | T2 |
| C7 | Generic/custom-profile handler for app-defined `typ` values | `ValidatorBuilder`, `MediaType::custom()` | T2 |
| C8 | Security Event Token consumer (receiving RISC/CAEP-style events) | `SetProfile::consumer()` | T3 |
| C9 | Revocation: `TokenDenylistInterface` checked on `jti`, with `NullDenylist` (default), PSR-16 cache and Doctrine implementations | bundle | T2 |
| C10 | Freshness policy: `max_token_age` (reject old `iat` even if `exp` is generous), configurable `leeway`, injectable PSR-20 clock | library validator + handler | T1 (leeway/clock), T2 (max age) |
| C11 | Multi-issuer / multi-tenant: pick the consumer by the token's `iss` (or by host/tenant resolver) before validation, with a strict allowlist | `CompositeResolver`, bundle dispatcher | T3 |
| C12 | Encrypted (JWE) and nested JWT support on the consumer side | `NestedJwtParser`, `Decrypter` | T3 |
| C13 | `ScopeVoter` + `#[IsGranted('SCOPE_x')]`-style checks and an `is_granted_scope()` expression function | Symfony voters | T2 |
| C14 | Audience policy: accept a list of audiences, or require exact match per consumer | library consumer | T2 |
| C15 | Anonymous-friendly mode: verify a token if present, don't 401 when absent (public endpoints with optional identity) | custom authenticator or firewall config | T3 |

### 3.2 Issuer side — minting tokens

| # | Capability | Backed by | Tier |
|---|---|---|---|
| I1 | `AccessTokenIssuer::issue(subject, audience, scopes, ttl, extraClaims): string` | `AccessTokenProfile::issuer()` | T1 |
| I2 | Named issuers (different audiences/keys/TTLs per client or tenant) | config tree §4 | T2 |
| I3 | `TokenClaimProviderInterface` tagged services — apps contribute claims (tenant, email, entitlements) without subclassing the issuer | DI tags | T2 |
| I4 | `JwtIssuingEvent` (mutable claims) + `JwtIssuedEvent` (audit hook) | EventDispatcher | T2 |
| I5 | Login integration: an authentication success handler that returns `{ "access_token": ..., "token_type": "Bearer", "expires_in": ... }`, pluggable into `json_login`/`form_login` | Symfony + I1 | T1 |
| I6 | `IdTokenIssuer` for apps acting as an OIDC provider | `IdTokenProfile::issuer()` | T3 |
| I7 | Security Event Token issuer (emit RISC/CAEP events to relying parties) | `SetProfile::issuer()` | T3 |
| I8 | Encrypted/nested issuance (sign-then-encrypt) | `NestedJwtBuilder` | T3 |
| I9 | Refresh-token *contract* only: `RefreshTokenStoreInterface` + an opaque-token generator, with an optional Doctrine implementation in a separate sub-package; JWT-based refresh tokens are deliberately not offered | bundle | T3 (see §8) |

### 3.3 Key management

| # | Capability | Backed by | Tier |
|---|---|---|---|
| K1 | Key sources: inline/env secret, base64 secret, PEM file, JWK file, JWKS file, Symfony Secrets vault, custom service | `HmacKey`, `RsaPrivateKey::fromPem()`, `JwkParser`, `JwkSet` | T1 (env secret), T2 (rest) |
| K2 | Named key registry with `kid`, so config refers to keys by name | `JwkSet`, `KeyResolver` | T2 |
| K3 | Rotation: one *active* signing key, N *accepted* verification keys; rotating = adding a key and flipping `active`, no downtime | `StaticJwkSetResolver` | T2 |
| K4 | JWKS publisher endpoint (`/.well-known/jwks.json`) exposing public keys only, with cache headers, opt-in route import | `JwkSet::toArray()` + controller | T2 |
| K5 | Remote JWKS consumption (`jwks_uri`) with PSR-18 client + PSR-16 cache, HTTPS-only, bounded body, throttled refresh-on-miss | `RemoteJwksResolver` (already implemented in the library) | T2 |
| K6 | Composite resolution: remote JWKS with local fallback so an IdP outage doesn't break verification of still-valid keys | `CompositeResolver` | T2 |
| K7 | OIDC discovery: fetch `jwks_uri` (and issuer metadata) from `/.well-known/openid-configuration` instead of hard-coding it | bundle + PSR-18 | T3 |
| K8 | Publish an issuer discovery document for apps acting as an OP/AS (RFC 8414) | bundle controller | T3 |
| K9 | Key material never appears in the profiler, logs, exception messages, or `debug:container` parameter dumps | bundle hardening | T1 |

### 3.4 Observability & operations

| # | Capability | Backed by | Tier |
|---|---|---|---|
| O1 | PSR-3 logging on a dedicated `jwt` Monolog channel, with the library's redacting `SecurityLog` and configurable levels | `SecurityLog`, `LogLevels` | T1 |
| O2 | Profiler / web-debug-toolbar panel: tokens seen this request, decoded header + claims (redacted), validation verdict and reason, key/kid used, verification timing | `DataCollector` | T2 |
| O3 | Events for authentication success/failure carrying the *reason* (expired vs. bad signature vs. wrong audience) for metrics and alerting | EventDispatcher | T2 |
| O4 | RFC 6750 `WWW-Authenticate` response headers with correct `error`/`error_description` on 401 — without leaking why validation failed beyond the standard codes | entry point | T2 |
| O5 | Health/self-check: a command that validates configuration (keys parse, algorithms match key types, JWKS reachable) — CI- and deploy-gate friendly | Command | T2 |

### 3.5 Developer experience

| # | Capability | Tier |
|---|---|---|
| D1 | `jwt:token:create` — mint a token from CLI for local testing (subject, audience, scopes, TTL, named issuer) | T2 |
| D2 | `jwt:token:inspect` — decode and verify a token, printing header/claims/verdict with human-readable failure reasons | T2 |
| D3 | `jwt:key:generate` — generate HMAC secret / RSA / EC / OKP keypair in PEM or JWK, with `kid` | T2 |
| D4 | `jwt:jwks:dump` — print the public JWK Set (what K4 would serve) | T2 |
| D5 | Test helpers shipped in `src/Test/`: a `TestTokenFactory` for functional tests, assertion helpers, a frozen-clock service alias for time-travel tests | T2 |
| D6 | Flex recipe: registers the bundle, writes a starter `config/packages/medzuch_jwt.yaml` and `.env` entries | T3 |
| D7 | Documentation: quickstart per role (resource server / auth server / OIDC RP), config reference, cookbook (rotation, multi-tenant, SPA cookies), upgrade notes | T2 |
| D8 | Compile-time configuration validation: unknown algorithm names, key/algorithm mismatch (e.g. `RS256` with an HMAC key), missing `jwks_uri` dependencies — all fail at container build, not at first request | T1 |

### 3.6 Advanced / standards-track (T3)

- **DPoP (RFC 9449)** — sender-constrained tokens: verify the `cnf.jkt`
  thumbprint against a `DPoP` proof header. Needs a custom authenticator
  (the native `access_token` one has no hook for a second header) plus replay
  protection on the proof's `jti` — reuses C9's denylist.
- **mTLS-bound tokens (RFC 8705)** — compare `cnf.x5t#S256` to the client
  certificate the proxy forwarded.
- **Token exchange (RFC 8693)** and **client credentials** helpers for
  service-to-service calls; an outbound `HttpClient` decorator that attaches a
  cached machine token to internal API calls.
- **Introspection fallback (RFC 7662)** for deployments mixing JWT and opaque
  tokens behind one firewall.
- **Proof-of-possession key generation** and JWE-encrypted claims for tokens
  that traverse untrusted intermediaries (C12/I8).

---

## 4. Configuration design (`medzuch_jwt`)

Named collections everywhere; the simplest useful configuration stays short.

**Minimal (symmetric key, one API firewall, app is both issuer and consumer):**

```yaml
medzuch_jwt:
  keys:
    default:
      hmac: '%env(JWT_SECRET)%'

  issuers:
    default:
      issuer: '%env(APP_URL)%'
      key: default
      algorithm: HS256
      audience: '%env(APP_URL)%'
      ttl: 900

  consumers:
    default:
      issuer: '%env(APP_URL)%'
      audience: '%env(APP_URL)%'
      keys: [default]
      allowed_algorithms: [HS256]
```

**Full tree (illustrative — every non-MVP branch is optional):**

```yaml
medzuch_jwt:
  clock: null                       # service id of a PSR-20 clock; default SystemClock
  logger: 'monolog.logger.jwt'      # null disables logging
  log_levels: { failure: warning, success: debug }

  keys:
    hmac_default:  { hmac: '%env(JWT_SECRET)%' }
    rsa_2026:      { pem_private: '%kernel.project_dir%/config/jwt/private.pem',
                     pem_public:  '%kernel.project_dir%/config/jwt/public.pem',
                     kid: '2026-01', active: true }     # unencrypted PEM only — see §9.4
    rsa_2025:      { pem_public: '...', kid: '2025-01' }     # still accepted, no longer signing
    idp_remote:    { jwks_uri: 'https://idp.example.com/.well-known/jwks.json',
                     http_client: 'http_client', cache: 'cache.app',
                     cache_ttl: 300, fallback_keys: [rsa_2025] }

  issuers:
    default:
      profile: access_token          # access_token | id_token | set | custom
      issuer: '%env(APP_URL)%'
      key: rsa_2026
      algorithm: RS256
      audience: ['%env(APP_URL)%']
      ttl: 900
      client_id: '%env(APP_CLIENT_ID)%'
      claims: { }                    # static extra claims; dynamic ones via I3/I4

  consumers:
    api:
      profile: access_token
      issuer: '%env(APP_URL)%'
      audience: '%env(APP_URL)%'
      keys: [rsa_2026, rsa_2025]
      allowed_algorithms: [RS256]
      leeway: 0
      max_token_age: null
      denylist: null                 # service id implementing TokenDenylistInterface
      user:
        mode: provider               # provider | claims | custom
        identity_claim: sub
        roles: { claim: scope, prefix: 'ROLE_', separator: ' ' }   # omit to disable
    partner_idp:
      profile: id_token
      issuer: 'https://idp.example.com'
      audience: '%env(OIDC_CLIENT_ID)%'
      keys: [idp_remote]
      allowed_algorithms: [RS256, ES256]
      user: { mode: custom, service: App\Security\ProvisionUserFromIdToken }

  jwks:
    publish:
      enabled: false
      path: '/.well-known/jwks.json'
      keys: [rsa_2026, rsa_2025]     # public halves only
      cache_max_age: 300
```

Design notes:

- **`keys` is a map, not a scalar, from v0.1** even though the MVP only
  exercises one entry — this is the retrofit that would otherwise break BC.
- **Key/algorithm compatibility is validated at container build** (D8): the
  library's `SigningAlgorithm` implementations are per-algorithm classes (not an
  enum), each narrowing to its key family and throwing `KeyMismatchException` at
  runtime; the bundle maps the configured names to those services and rejects
  impossible pairings before the app ever boots a request.
- **A firewall names a consumer**, not a profile:
  `token_handler: medzuch_jwt.handler.api`. A shorthand firewall key
  (`medzuch_jwt: { consumer: api }`) via an authenticator factory is a T2
  convenience over the same service.
- **No secret ever lands in a container parameter** that `debug:container`
  would print (K9): keys are built inside factory services from env references.

---

## 5. Service wiring (DI)

Registered from `loadExtension()` into `config/services.php`:

- `medzuch_jwt.key.<name>` — factory services building `Key` objects from each
  configured source; public halves separated from private ones so the JWKS
  publisher can never expose a private key.
- `medzuch_jwt.key_resolver.<name>` — `StaticJwkSetResolver`,
  `RemoteJwksResolver` or `CompositeResolver`, depending on the key entry.
- `medzuch_jwt.consumer.<name>` — the library consumer built via a static
  factory (`AccessTokenProfile::consumer(...)` etc.).
- `medzuch_jwt.handler.<name>` — our `AccessTokenHandlerInterface`
  implementation wrapping the consumer plus policy (denylist, max age, user
  mode). Referenced from `security.yaml`.
- `medzuch_jwt.issuer.<name>` — token-minting service; the `default` one is
  aliased to `AccessTokenIssuerInterface` for autowiring.
- `medzuch_jwt.clock` — alias to a PSR-20 clock; defaults to the library's
  `SystemClock`, swappable to `FrozenClock` in tests.
- `medzuch_jwt.logger` — optional PSR-3 logger (`jwt` Monolog channel).
- `medzuch_jwt.role_mapper.<name>`, `medzuch_jwt.user_resolver.<name>` — only
  registered when the corresponding config branch is present.
- Autoconfiguration tags: `medzuch_jwt.claim_provider` (I3),
  `medzuch_jwt.token_extractor` (C5), `medzuch_jwt.denylist` (C9).
- Compiler pass validating cross-references (unknown key name, key/alg
  mismatch, consumer referenced by no firewall, JWKS publish listing a key with
  no public half).

---

## 6. End-to-end flows

### 6.1 Login → issue

```
POST /api/auth/login  →  app verifies credentials (its own logic)
  → AccessTokenIssuer::issue(subject: $user->getId(), ttl: 900)
      ├─ TokenClaimProviders contribute extra claims          (I3)
      ├─ JwtIssuingEvent lets listeners adjust them           (I4)
      └─ AccessTokenProfile::issuer($iss, $alg, $key)->issue()
             ->subject(...)->audience(...)->expiresIn(...)->build()
  → JSON { "access_token": "...", "token_type": "Bearer", "expires_in": 900 }
```

Whatever the app does alongside this — refresh tokens, cookies, device
records — is app logic; the bundle's boundary ends at the signed access token
(§8).

### 6.2 Request → authenticate

```
GET /api/...  Authorization: Bearer <token>
  → stateless firewall, access_token authenticator
    → medzuch_jwt.handler.api::getUserBadgeFrom($token)
        ├─ consumer->parse($token): ClaimsSet   (signature, iss, aud, exp, typ, required claims)
        ├─ denylist check on jti                (C9, if configured)
        ├─ max_token_age check on iat           (C10, if configured)
        └─ UserBadge(identity claim) [+ claims-based user loader / role mapper]
    → user provider loads the user (mode: provider)
  → voters authorize (app voters, and/or ScopeVoter for claim-derived scopes)
  → controller
```

### 6.3 OIDC relying party (third-party IdP)

```
IdP issues an ID token  →  app's consumer "partner_idp"
  → keys resolved from the IdP's jwks_uri (cached, HTTPS-only, rotation-aware)
  → IdTokenProfile::consumer(..., expectedNonce: ...)->parse($token)
  → user mode: custom → JIT-provision or match a local user
```

### 6.4 Key rotation (no downtime)

```
1. Generate a new keypair            (jwt:key:generate, D3)
2. Add it to `keys` with a new kid, `active: false`
3. Deploy → the JWKS endpoint now publishes both public keys; consumers cache-refresh
4. Flip `active: true` on the new key → new tokens are signed with it
5. After max token TTL has elapsed, drop the old key entry
```

---

## 7. Phased roadmap

- **Phase 0 — Skeleton.** `AbstractBundle`, composer (`type: symfony-bundle`,
  requires `medzuch/jwt-php` + `symfony/security-bundle`), config tree shell,
  CI reusing the library's Docker QA gates (cs-fixer, PHPStan L9, PHPUnit), a
  functional test kernel. *(Not started.)*
- **Phase 1 — MVP (v0.1).** T1 items: named `keys`/`issuers`/`consumers` with
  one entry each, HMAC key from env, `AccessTokenHandler` + native firewall
  wiring, `AccessTokenIssuer`, login success handler, `provider` user mode,
  PSR-3 logging, compile-time config validation. Functional test proving
  issue → request → authenticated controller.
- **Phase 2 — Keys & rotation (v0.2).** K1–K4, K9: PEM/JWK sources, named keys,
  `kid` selection, active/accepted split, JWKS publisher, `jwt:key:generate`,
  RS256/ES256/EdDSA support end to end.
- **Phase 3 — Federation (v0.3).** K5–K6, C6, C14: remote JWKS with cache and
  fallback, ID-token consumer, OIDC-RP quickstart, audience lists.
- **Phase 4 — DX & hardening (v0.4 → v1.0).** C3–C5, C9, C10, C13, I2–I5,
  O2–O5, D1–D5, D7: user modes, role mapping, extractors, denylist, scope
  voter, claim providers, events, profiler panel, console commands, test
  helpers, documentation, `WWW-Authenticate` handling. **1.0 = the T1+T2 set,
  documented, with a BC policy.**
- **Phase 5+ — Standards-track (post-1.0).** §3.6: DPoP, mTLS binding, token
  exchange, introspection fallback, JWE/nested tokens, SET issue/consume,
  multi-tenant issuer dispatch, discovery documents, Flex recipe.

Each phase is shippable on its own and adds no required configuration to
applications already running the previous one.

---

## 8. Deliberate non-goals

These stay outside the package boundary, permanently unless the reasoning
below changes:

1. **Refresh-token storage, rotation and revocation policy.** Refresh tokens
   should be opaque, hashed at rest, single-use with rotation, and tied to the
   app's own session/device model — that is business logic over the app's
   database, not JOSE. The bundle may ship a *contract* (I9) so app code has a
   shape to implement, but no schema, no entity, no default persistence.
2. **A user entity, user provider, or login form.** Symfony already provides
   these; the bundle consumes them.
3. **An OAuth 2.0 authorization-server implementation.** Consent screens,
   grant types, client registration, PKCE — a different (much larger) package.
   The bundle only mints and verifies the tokens such a server would use.
4. **Session-based authentication.** The bundle is for stateless bearer flows;
   a JWT stored in a server-side session is a session with extra steps.
5. **Re-exporting the library's API.** Apps that need raw JWS/JWE handling use
   `medzuch/jwt-php` directly; the bundle wires the *profiles*, it does not
   proxy every class.
6. **Encoding authorization state in tokens as the default.** The bundle makes
   claim-derived roles possible (C4/C13) but never automatic: stale-privilege
   bugs from long-lived claims are a real hazard, and the safe default is a
   token that carries identity while authorization reads current state.

---

## 9. Open questions

1. **Own firewall key or native `access_token` only?** A `medzuch_jwt:` firewall
   shorthand is nicer DX but adds a security-bundle extension point to maintain
   across Symfony versions. Leaning: native only for 0.1, shorthand in Phase 4
   as an additive convenience.
2. **Symfony 6.4 support from day one, or 7.x first?** 6.4 is LTS and widely
   deployed; the cost is CI matrix breadth and avoiding 7.x-only APIs. Leaning:
   both from Phase 1, since the divergence in the APIs used here is small.
3. **Doctrine denylist in-tree or as a separate package?** Shipping a Doctrine
   entity in a security bundle drags a heavy optional dependency and migration
   concerns. Leaning: interface + PSR-16 implementation in-tree, Doctrine in a
   separate `medzuch/jwt-bundle-doctrine` if demand appears.
4. **Upstream (library) gaps that limit what the bundle can offer.** Four,
   all recorded library-side in `medzuch/jwt-php` `docs/09-symfony-bundle-plan.md`:
   (a) none of the profile `consumer()` factories accepts a leeway argument, so
   the `leeway` config key (§4) cannot be honoured without abandoning the
   profile and hand-building a `ValidatorBuilder` — which would lose `typ`
   pinning and the required-claim set; (b) `AccessTokenProfile::consumer()`
   takes a single `string $expectedAudience`, blocking multi-audience consumers
   (C14), even though `ValidatorBuilder::expectAudience()` already accepts an
   array; (c) `RsaPrivateKey::fromPem()` and `EcPrivateKey::fromPem()` cannot open a
   passphrase-protected PEM, so the bundle's PEM key source can only accept
   unencrypted private keys — a real operational limit when keys are shipped as
   encrypted files; (d) the library pins `"php": "~8.3.0"`, which caps *below*
   8.4 — the bundle cannot support PHP 8.4 until that is loosened upstream. All
   four are BC-safe to fix in a library 1.1; (a) and (b) should land before the
   bundle's Phase 1 freezes its config semantics.
5. **Package naming for `kid`-less symmetric setups** — whether `keys.default.hmac`
   should auto-derive a `kid` (helps future rotation, changes token headers) or
   stay `kid`-less (simplest, matches most HS256 deployments today).

---

*Library API touchpoints (verified against `medzuch/jwt-php` `src/`):*
*`AccessTokenProfile::issuer()/consumer()`, `IdTokenProfile`, `SetProfile`,*
*`ProfileConsumer::parse(string): ClaimsSet` (throws `JwtException`),*
*`AccessTokenBuilder` (`subject/audience/scope/clientId/expiresIn/withClaim/build`),*
*`ClaimsSet` accessors, `JwkSet`/`JwkParser`, `KeyResolver` with*
*`StaticJwkSetResolver` / `RemoteJwksResolver` / `CompositeResolver`,*
*`HmacKey`/`RsaPrivateKey::fromPem()`/`EcPrivateKey`/`OkpPrivateKey`,*
*`SigningAlgorithm` implementations (`Hs256`…`Es512`, `EdDsa`),*
*`MediaType`, `NestedJwtBuilder`/`NestedJwtParser`, PSR-20 `SystemClock`/`FrozenClock`,*
*PSR-3 logging via `SecurityLog`/`LogLevels`.*
