# medzuch/jwt-bundle — Design Plan (v0.5)

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
> **Status.** This is v1.1.1, a security patch over v1.1.0: the guard that
> refuses a token minted for something else was reading its header through a
> media-type comparison `medzuch/jwt-php` 1.2.0 got wrong, so the floor is now
> `^1.2.1` and the guard covers Security Event Tokens beside access tokens.
> Phase 5 also closed I9, the refresh-token contract, which is a shape rather
> than an implementation — §8.1 keeps the storage out permanently.
> Phase 5 shipped the pairs whose library half
> already existed — encrypted tokens read and minted (C12, I8), Security Event
> Tokens received and transmitted (C8, I7), ID tokens issued beside the
> verification 1.0 had (I6) — and the rows that needed nothing from the library
> at all: a key set addressed by issuer identifier (K7), this application's own
> metadata document (K8) and several tenants behind one firewall (C11). C15
> needed no code anywhere: Symfony's own authenticator already declines a
> request carrying no token, so optional identity is firewall configuration,
> documented and pinned by the suite. Still open in the phase: DPoP and mTLS
> binding, token exchange, introspection and D6's Flex recipe.
>
> Phases 0 through 4 of §7 shipped in v1.0.0: PEM and JWK
> key sources, named keys and rotation, the JWKS publisher, `jwt:key:generate`;
> federation — remote JWK Sets with local fallback (K5, K6), ID-token
> verification (C6) and the audience policy (C14); and Phase 4's DX and
> hardening — C3's remaining modes, C4, C5, C9, C13, O4, the issuance hooks
> I3/I4, O3, the console commands D1/D2/D4/O5, the test helpers D5, the profiler
> panel O2, the documentation D7, C10's freshness ceiling, C7's custom token
> types, O1's log levels and K9. EdDSA works end to end, since the JWK source is
> the only one RFC 8037 gives it. Issue #3 is closed: a compiler pass refuses a
> configuration naming a service this application does not have.
>
> **The T1+T2 set is complete**, which is §7's own test for 1.0 — "the T1+T2 set,
> documented, with a BC policy". The BC policy is written and enforced by the
> suite; the last two capability rows were C7 and C10's max-age half, neither of
> which had been assigned to a phase, and both landed in Phase 4. Phase 5+ is
> the T3 rows, off by default and additive, on the far side of a promise that a
> 1.x release will not move what is already there — which is how v1.1.0 could
> add eight of them, and C15 beside them, and stay a minor.
>
> **v0.5 change.** The design decisions are made: v0.4's five open questions are
> now §9's five recorded decisions, each with its reasoning and what would
> reopen it. Two change the plan's shape — there will be no `medzuch_jwt:`
> firewall shorthand (DEC-1), and the supported window is Symfony
> `^6.4 || ^7.4 || ^8.0` on PHP 8.3/8.4 (DEC-2), v0.4 having predated Symfony 7.4
> LTS and 8.0. The four upstream library gaps are closed: `medzuch/jwt-php`
> 1.1.0 added profile leeway, multi-audience consumers, passphrase-protected
> PEMs and PHP 8.4, and the package is on Packagist — nothing outside this
> repository blocks Phase 1 (DEC-4).

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
6. **Target versions.** PHP 8.3 and 8.4 (the library's window), Symfony 6.4 LTS,
   7.4 LTS and 8.x — DEC-2 in §9 has the matrix and why 7.0–7.3 are excluded.
   `symfony/security-bundle` is a hard requirement; HTTP client, cache,
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
│   ├── MedzuchJwtBundle.php       # AbstractBundle: what Symfony calls, and nothing else
│   ├── Security/                  # token handlers, user resolution, voters, denylist
│   ├── Issuer/                    # token-minting services, claim providers
│   ├── Key/                       # key source loaders, key registry, rotation
│   ├── Jwks/                      # JWKS publisher controller + remote JWKS wiring
│   ├── Event/                     # dispatched events
│   ├── Command/                   # console commands (jwt:key:generate)
│   ├── DataCollector/             # profiler panel and the pass that wires it
│   ├── DependencyInjection/       # the config tree, the registration, the refusals, the passes
│   └── Test/                      # test helpers shipped to consumers
├── config/
│   ├── services.yaml              # the clock, and nothing else
│                                  # (no routes.php: DEC-6 leaves routing to the app)
├── docs/
│   ├── plan.md                    # this file
│   └── cookbook.md                # recipes: the features assembled into tasks
├── README.md                      # the reference: every feature, one at a time
├── UPGRADE.md                     # what each release asks of an application
├── BACKWARD-COMPATIBILITY.md      # what 1.0 freezes, and how it may change
└── tests/                         # unit + functional (real test kernel)
```

Key mechanics that shape the design:

- **Registration.** `Medzuch\JwtBundle\MedzuchJwtBundle::class => ['all' => true]`
  in `config/bundles.php`, or automatically via a Flex recipe (§3.5).
- **`AbstractBundle::configure()`** defines the config tree; **`loadExtension()`**
  reads the validated config and registers/parameterizes services.
- **Config root key** `medzuch_jwt`; namespace `Medzuch\JwtBundle\`; composer
  name `medzuch/jwt-bundle`.
- **Configuration is YAML on both sides** — `config/services.yaml` inside the
  bundle, `config/packages/medzuch_jwt.yaml` in the application. PHP service
  config would put class names under static analysis, but the file holds one
  service and the functional suite asserts its type on every run, so the check
  is already there. The cost is a `symfony/yaml` requirement, which is present
  in every Symfony application that configures anything.
- **Firewall integration** goes through Symfony's native `access_token` block
  and a token-handler service. The bundle deliberately does **not** implement
  `AuthenticatorFactoryInterface` and ships no firewall key of its own (DEC-1 in
  §9).
- **`DependencyInjection/` holds the work, the bundle class holds the hooks.**
  `AbstractBundle` invites both the tree and the registration into the bundle
  class, and taking that invitation cost 2,010 lines in one file. They live next
  door instead, as `@internal` classes the bundle delegates to on the first line
  of each hook: `ConfigurationTree` (the tree), `ServiceRegistrar` (definitions),
  `ConsoleCommands` (the five commands, skipped whole where `symfony/console` is
  absent), `ConfigurationGuard` (refusals that need more than one node to
  decide) and `KeyEntries` (the normalised `keys:` section). The compiler passes
  and the object they read were already there.

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
| C3 | User resolution modes `provider` / `claims` / `custom` (§2.2) incl. a `JwtUser` value object carrying the claim set. One resolver per mode, so the handler holds a collaborator rather than nullable options encoding three behaviours | `ClaimsSet` | T1 (`provider`), T2 (rest) |
| C4 | Claim → role mapping (`scope`, `roles`, `groups`, custom), configurable prefix, separator and baseline. Only mode `claims` reads it: elsewhere the provider or the factory decides, and a mapping nothing reads is refused at build | `ClaimsSet::get()` | T2 |
| C5 | Token extractors: the cookie one, which Symfony does not ship; `header`, `query_string` and `request_body` are native and re-spelling them would be names to learn for nothing. Ships with the CSRF trade documented, and an opt-in `Sec-Fetch-Site` check that is defence in depth rather than a defence | `CookieTokenExtractor` + native | T2 |
| C6 | ID-token verifier for OIDC relying-party flows (`nonce`, `azp`). A service the application calls from its callback, **not** a firewall authenticator (DEC-8). `at_hash` is not checked: the library has no support for it, and the bundle does not reimplement crypto its library is missing | `IdTokenProfile::consumer()` | T2 |
| C7 | Generic/custom-profile handler for app-defined `typ` values: `consumers.*.token_type` and `required_claims`, replacing the RFC 9068 posture and nothing else about a consumer. Built on `ValidatorBuilder` rather than as a fourth profile — the library documents that layer as the one for custom flows, and its consumer constructors are `@internal` | `ValidatorBuilder`, `MediaType::custom()` | T2 |
| C8 | Security Event Token consumer (receiving RISC/CAEP-style events). **Landed in Phase 5** as `security_events.consumers`. Replay detection is the receiver's: a SET has no `exp` (RFC 8417 §4.1.4), so the denylist — whose contract takes the moment an entry may be forgotten — is not the seam for it | `SetProfile::consumer()` | T3 |
| C9 | Revocation: `TokenDenylistInterface` checked on `jti`, PSR-16 cache implementation, and the denylist registered as a service the application can revoke through. No `NullDenylist`: unconfigured means no service and no lookup, which is the same default said with less | bundle | T2 |
| C10 | Freshness policy: `max_token_age` (reject old `iat` even if `exp` is generous), configurable `leeway`, injectable PSR-20 clock. The max age is the handler's own check rather than the library's — `ValidatorBuilder` has no notion of one — and carries its own `RejectionReason`, since an application's ceiling and an issuer's expiry are different facts about different clocks | library validator + handler | T1 (leeway/clock), T2 (max age) |
| C11 | Multi-issuer / multi-tenant: pick the consumer by the token's `iss` before validation, with a strict allowlist. **Landed in Phase 5** as `dispatchers.<name>`, whose routing table is the listed consumers themselves — each already declares the `iss` it expects, so the value is written once and an env reference still works. Reading an unverified `iss` is safe because choosing a judge grants nothing: the consumer selected asks every question it would have asked anyway, on its own keys. No fallback consumer, and a host/tenant resolver is the application's own handler rather than a second selection strategy here | bundle dispatcher | T3 |
| C12 | Encrypted (JWE) and nested JWT support on the consumer side. **Landed in Phase 5** as `consumers.<name>.jwe` over a `jwe_keys` registry, as a decorator in front of the verifier the consumer already had — so encryption changes what arrives and nothing about what is then checked. A bare signed token is refused once the block is there, with no opt-out: an attacker able to strip the outer layer and be believed would have taken the confidentiality for the cost of two segments. Symmetric key management only (`dir` and the AES key-wrapping schemes); `Decrypter` rather than `NestedJwtParser`, whose one entry point would verify the inner signature a second time under a second copy of the same allowlist | `Decrypter` | T3 |
| C13 | `ScopeVoter` + `#[IsGranted('SCOPE_x')]`-style checks and an `is_granted_scope()` expression function. Scopes are read from the `scope` claim — the RFC's delimited string or a JSON list — through a `ProvidesScopes` user, so what decides is the user rather than the mode: `claims` builds one, a `custom` factory can, and so can a store-loaded user. The claim name is not configurable; `scp` and its like belong to a custom factory | Symfony voters | T2 |
| C14 | Audience policy per consumer: `any` (RFC 7519 §4.1.3, the default) or `exclusive` — refuse a token addressed to anyone else, as RFC 9068 §3 asks. Not "exact match": a consumer answering to two names is addressed by either, so requiring the token to name *all* of them would refuse a legitimate one | library consumer + `AccessTokenHandler` | T2 |
| C15 | Anonymous-friendly mode: verify a token if present, don't 401 when absent (public endpoints with optional identity). **Landed in Phase 5 as firewall configuration, not code**: Symfony's `access_token` authenticator declines a request carrying no token rather than failing it, so an access rule exempting the path is the whole feature. The authenticator this row allowed for was not needed — see the correction to DEC-1 in §9 | firewall config (documented + pinned by tests) | T3 |

### 3.2 Issuer side — minting tokens

| # | Capability | Backed by | Tier |
|---|---|---|---|
| I1 | `AccessTokenIssuer::issue(subject, scopes, claims, ttl, audience): IssuedToken` — audience, client id and TTL come from configuration; each argument narrows it for one token. Returns a value object rather than a string so the lifetime travels with the token, instead of the caller re-deriving an `expires_in` it just asked for | `AccessTokenProfile::issuer()` | T1 |
| I2 | Named issuers (different audiences/keys/TTLs per client or tenant) | config tree §4 | T2 |
| I3 | `TokenClaimProviderInterface` autoconfigured services — apps contribute claims (tenant, email, entitlements) without subclassing the issuer. Handed a `TokenIssuance`, so a provider can serve one issuer of several; refused the claims the issuer decides itself, since a provider runs for tokens it was never asked about | DI tags | T2 |
| I4 | `JwtIssuingEvent` (mutable claims, dispatched last so it sees the whole set) + `JwtIssuedEvent` (audit hook, carrying the `jti` and never the token) | EventDispatcher | T2 |
| I5 | Login integration: an authentication success handler that returns `{ "access_token": ..., "token_type": "Bearer", "expires_in": ... }`, pluggable into `json_login`/`form_login` | Symfony + I1 | T1 |
| I6 | `IdTokenIssuer` for apps acting as an OIDC provider. **Landed in Phase 5** as `id_token_issuers`, a section of its own because `id_tokens` is the relying-party half and already public configuration. Hands back the library's builder, as I7 does and for the same reason — `nonce`, `auth_time`, `acr`, `amr` and the profile claims are what vary — while `sub` and the relying party's `client_id` are arguments, since OIDC Core §2 requires both and neither varies in that way. It also closed a confusion only one deployment holding both ends can reach: `IdTokenVerifier` now refuses a token typed `at+jwt` — in any spelling RFC 7515 §4.1.9 makes equivalent, which took the `medzuch/jwt-php` 1.2.1 floor to be true — or `secevent+jwt`, the pair RFC 8417 §4 is named after. No issuance events, no claim providers, no `at_hash` | `IdTokenProfile::issuer()` | T3 |
| I7 | Security Event Token issuer (emit RISC/CAEP events to relying parties). **Landed in Phase 5** as `security_events.issuers`. Hands back the library's builder rather than an argument list, since what varies between two SETs is the events; delivery (RFC 8935 push, RFC 8936 poll) stays the application's | `SetProfile::issuer()` | T3 |
| I8 | Encrypted/nested issuance (sign-then-encrypt). **Landed in Phase 5** as `issuers.<name>.jwe`, one key and one algorithm of each kind where the reading side takes lists — a receiver accepts what its senders still use, a sender picks. `replicated_claims` copies a claim into the outer header for an intermediary that holds no key (RFC 7519 §5.3), read back out of the signed token so the two cannot drift | `NestedJwtBuilder` | T3 |
| I9 | Refresh-token *contract* only: `RefreshTokenStoreInterface` + an opaque-token generator, with an optional Doctrine implementation in a separate sub-package; JWT-based refresh tokens are deliberately not offered. **Landed in Phase 5** as `Refresh\RefreshTokenStoreInterface`, `RefreshToken`, `RefreshTokenRecord` and `medzuch_jwt.refresh_token_generator`. `consume()` spends a token and reports a previous spend in one call, because a `find()` and a `delete()` have a window between them and that window is where a token is used twice; a record that comes back `alreadyUsed` is what OAuth 2.1 §6.1 asks an application to react to. No configuration section: the lifetime belongs to the flow that mints the token, and a `refresh_tokens` key would advertise persistence this package does not have | bundle | T3 (see §8) |

### 3.3 Key management

| # | Capability | Backed by | Tier |
|---|---|---|---|
| K1 | Key sources: inline/env secret, base64 secret, PEM file, JWK file, Symfony Secrets vault. No custom key *service*: a secret arrives as an env reference and a document as a path, which is every case anyone brought, and a service id would be a seam with nothing behind it. A whole **JWKS file** is not one: a set says nothing at build time about which keys a consumer can verify with or which two a token could not tell apart, and consuming a set is what K5 does over HTTP | `HmacKey`, `RsaPrivateKey::fromPem()`, `JwkParser`, `JwkSet` | T1 (env secret), T2 (rest) |
| K2 | Named key registry with `kid`, so config refers to keys by name | `JwkSet`, `KeyResolver` | T2 |
| K3 | Rotation: an issuer signs with one key, a consumer accepts several; rotating = adding a key, accepting it, then signing with it, no downtime. Needs no `active` flag — `issuers.<name>.key` already says which key is active, and a second spelling could disagree with it | `StaticJwkSetResolver` | T2 |
| K4 | JWKS publisher exposing public keys only, with cache headers and an `ETag`; the application routes to it (DEC-6). Publishing a symmetric key is refused at container build | `JwkSet::toArray()` + controller | T2 |
| K5 | Remote JWKS consumption (`jwks_uri`) with PSR-18 client + PSR-16 cache, HTTPS-only, bounded body, throttled refresh-on-miss. Named at the top level, so two consumers of one issuer share a cache entry and a refresh window | `RemoteJwksResolver` (already implemented in the library) | T2 |
| K6 | Composite resolution: remote JWKS with local fallback so an IdP outage doesn't break verification of still-valid keys. Local first, so the common path is not a round trip | `CompositeResolver` | T2 |
| K7 | OIDC discovery: fetch `jwks_uri` (and issuer metadata) from `/.well-known/openid-configuration` instead of hard-coding it. **Landed in Phase 5** as `remote_jwks.<name>.discovery`, and first of the phase — it needed nothing from the library | bundle + PSR-18 | T3 |
| K8 | Publish an issuer discovery document for apps acting as an OP/AS (RFC 8414). **Landed in Phase 5** as `metadata`, closing the pair with K7. Only `issuer` and `jwks_uri` are filled in — the two members a JWT bundle knows — and the rest arrives from `extra`, because everything else describes the authorization server §8 keeps out. A document that would not survive being read back — a missing or malformed `response_types_supported`, a plaintext identifier, an issuer carrying a query — is refused before it is served, and the identifiers are checked again when the service is built, since that is the only moment a `%env(...)%` has a value | bundle controller | T3 |
| K9 | Key material never appears in the profiler, logs, exception messages, or `debug:container` parameter dumps | bundle hardening | T1 |

### 3.4 Observability & operations

| # | Capability | Backed by | Tier |
|---|---|---|---|
| O1 | PSR-3 logging on a dedicated `jwt` Monolog channel, with the library's redacting `SecurityLog` and configurable levels. `log_levels` covers all seven categories the library emits, as named arguments so an unset one keeps the library's default rather than a copy of it; the two JWE ones arrived with C12, which is the first thing here with a JWE to log about | `SecurityLog`, `LogLevels` | T1 |
| O2 | Profiler panel: every token a consumer was shown, the verdict and the O3 reason behind a refusal, the `alg` and `kid` it named, the identity it would have authenticated as, and the milliseconds spent. The token itself is never collected — profiler data outlives the request on disk. Wired by decorating the handler the firewall calls, which is a `ChildDefinition` of ours rather than our service | `DataCollector` | T2 |
| O3 | `JwtVerifiedEvent` and `JwtRejectedEvent`, the latter carrying a `RejectionReason` — a small stable vocabulary rather than a case per library exception, since a dashboard should not have to learn a new name every time the library grows a leaf. `keys_unavailable` is kept apart from every other reason: an unreachable issuer is an outage, not a verdict on the token | EventDispatcher | T2 |
| O4 | RFC 6750 `WWW-Authenticate` on refusals. Symfony already answers a rejected token with `error="invalid_token"` and a generic description, so what the bundle adds is the challenge for a request carrying no credentials — no `error`, per §3 — and the `insufficient_scope` 403 naming the scope that would have sufficed (§3.1) | entry point + access denied handler | T2 |
| O5 | `jwt:config:check`: builds every key, consumer, issuer and verifier the container left for later, and reaches every remote set. What it adds to the build-time refusals is the material behind the configuration — a key file nobody deployed, an empty env variable, an unreachable issuer — which are factory arguments and so fail on the first request instead. Exit status gates a deploy step; `--skip-remote` reports what it skipped | Command | T2 |

### 3.5 Developer experience

| # | Capability | Tier |
|---|---|---|
| D1 | `jwt:token:create` — mint a token from CLI (subject, audience, scopes, TTL, extra claims, named issuer) through the configured issuer, so providers and issuing listeners run as they would in the application. `--raw` for a shell to capture; registered only where an issuer is | T2 |
| D2 | `jwt:token:inspect` — decode with no configuration at all, verify through the consumer's own handler where there is one, and name the O3 reason a refusal keeps off the wire. Reads a token from a pipe; exit status says accepted, refused, or not a JWT | T2 |
| D3 | `jwt:key:generate` — generate HMAC secret / RSA / EC / OKP keypair in PEM or JWK, with `kid`, and print the configuration that uses it. Refuses to overwrite a key file and writes the private half 0600 | T2 |
| D4 | `jwt:jwks:dump` — print the public JWK Set from the same `JwkSet` service K4 serves, so a document written to a file cannot drift from the one served over HTTP. `--compact` is byte for byte what the endpoint returns | T2 |
| D5 | Test helpers shipped in `src/Test/`: `TestTokenFactory`, which mints the tokens an issuer will not — expired, not yet valid, addressed elsewhere, from another issuer — and reads no configuration, so a test cannot pass by agreeing with a mistake it shares; `AssertsBearerChallenges` for what a refusal carried. Time travel needs no helper: `clock` already takes any PSR-20 service | T2 |
| D6 | Flex recipe: registers the bundle, writes a starter `config/packages/medzuch_jwt.yaml` and `.env` entries | T3 |
| D7 | Documentation: the README as the feature reference with a quickstart per role, `docs/cookbook.md` for the recipes that assemble several features into one task (machine tokens, two issuers on one API, tenants, an SPA on a cookie, a deploy gate), `UPGRADE.md` for what a release asks of an application already running, and `config:dump-reference` for the exhaustive tree — generated rather than hand-written, since a copy drifts. Every example is compiled into a real container and every link resolved, by the suite | T2 |
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
- **Proof-of-possession key generation**. JWE-encrypted claims for tokens that
  traverse untrusted intermediaries are C12, landed in Phase 5 on the consumer
  side, with I8 the issuing half beside it. Encrypting to a third party's
  public key (ECDH-ES) waits on a registry of asymmetric encryption keys and a
  way to publish this application's own.

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
      client_id: '%env(APP_CLIENT_ID)%'
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
  clock: null                        # service id of a PSR-20 clock; default SystemClock
  logger: 'monolog.logger.jwt'       # null disables logging

  log_levels:                        # each optional; unset keeps the library's own default
    accepted: info
    claim_rejected: warning
    key_resolution_failed: critical

  keys:
    rsa_2026:
      pem_private: '%kernel.project_dir%/config/jwt/private.pem'
      pem_passphrase: '%env(JWT_KEY_PASSPHRASE)%'
      pem_public: '%kernel.project_dir%/config/jwt/public.pem'
      algorithm: RS256
      kid: '2026-01'
    rsa_2025:                        # still accepted, no longer signing
      pem_public: '%kernel.project_dir%/config/jwt/public-2025.pem'
      algorithm: RS256
      kid: '2025-01'

  jwe_keys:                          # keys for encrypted tokens; separate from `keys` (RFC 7517 §4.2)
    payload_2026:
      secret: '%env(base64:JWT_JWE_SECRET)%'
      algorithm: A256KW
      kid: 'enc-2026'

  remote_jwks:                       # a set the issuer publishes, named once and shared
    partner_idp:
      uri: 'https://idp.example.com/.well-known/jwks.json'
      http_client: psr18.http_client
      cache_pool: cache.app
      cache_ttl: 300
      min_refresh: 60

  issuers:
    default:
      issuer: '%env(APP_URL)%'
      key: rsa_2026
      client_id: '%env(APP_CLIENT_ID)%'
      audience: ['%env(APP_URL)%']
      ttl: 900
      claims: { }                    # static extra claims; dynamic ones via I3/I4
      jwe:                           # seal what this issuer mints (I8)
        key: payload_2026
        key_management: A256KW
        content_encryption: A256GCM
        replicated_claims: [iss]     # copied into the outer header (RFC 7519 §5.3)

  consumers:
    api:
      issuer: '%env(APP_URL)%'
      audience: '%env(APP_URL)%'
      audience_policy: exclusive     # any | exclusive
      keys: [rsa_2026, rsa_2025]
      allowed_algorithms: [RS256]
      realm: api
      leeway: 0
      max_token_age: 300
      denylist: { cache_pool: cache.app }
      jwe:                           # read this consumer's tokens as encrypted ones (C12)
        keys: [payload_2026]
        allowed_key_management: [A256KW]
        allowed_content_encryption: [A256GCM]
      user:
        mode: claims                 # provider (default) | claims | custom
        identity_claim: sub
        roles: { claim: scope, prefix: 'ROLE_', separator: ' ' }   # claims mode only
    partner:                         # a third party's tokens, verified against their keys
      issuer: 'https://idp.example.com'
      audience: '%env(APP_URL)%'
      remote_jwks: partner_idp
      allowed_algorithms: [RS256, ES256]
      user: { mode: custom, factory: App\Security\TenantUserFactory }

  dispatchers:                       # one firewall, several tenants, the token choosing (C11)
    tenants:                         # a name of its own: a consumer's would be the same id
      consumers: [api, partner]
      realm: api

  token_extractors:
    spa_cookie:
      cookie: __Host-jwt
      same_site_only: true

  id_tokens:                         # OIDC relying party: a service, not a firewall (DEC-8)
    partner_idp:
      issuer: 'https://idp.example.com'
      client_id: '%env(OIDC_CLIENT_ID)%'
      remote_jwks: partner_idp
      allowed_algorithms: [RS256]

  id_token_issuers:                  # …and this application as the provider (I6)
    op:
      issuer: '%env(APP_URL)%'
      key: rsa_2026
      ttl: 300

  jwks:                              # the application routes to the controller itself (DEC-6)
    keys: [rsa_2026, rsa_2025]       # public halves only
    cache_max_age: 300
```

Both blocks are compiled into a real container by `DocumentationExamplesTest`,
which is what keeps this section from describing a configuration the bundle
stopped accepting. `config:dump-reference medzuch_jwt` prints the whole tree
with defaults and per-option prose; this is the shape, not the reference.

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
  (`medzuch_jwt: { consumer: api }`) via an authenticator factory was considered
  and refused: DEC-1 in §9 says why, and why a later DPoP authenticator would
  be a new firewall key of its own rather than this one. C15 was named here
  too, and is not: it turned out to need no authenticator at all — §9's
  Phase 5 correction says what it needed instead.
- **No secret ever lands in a container parameter** that `debug:container`
  would print (K9): keys are built inside factory services from env references.
- **`audience` is normalised to a list before it reaches the library.** jwt-php
  1.2.0 refuses a malformed array shape with a `LogicException`, and a YAML
  `audience:` written as a map is exactly what a config tree exists to catch:
  the tree accepts a scalar or a sequence, and `loadExtension()` rejects
  anything else — so the error names the offending config key instead of
  surfacing at the first request as a token problem.
- **`kid` is explicit, never derived** (DEC-5 in §9): optional for a single-key
  setup, required as soon as two keys share an algorithm — and always, for a
  `dir` encryption key, which nothing else can select.
- **Encryption keys are a registry of their own.** `keys` sign and verify,
  `jwe_keys` encrypt and decrypt; RFC 7517 §4.2 asks that one key serve one
  purpose, the two bind to algorithms from different registries, and the JWK Set
  publisher would otherwise have to learn to skip half of what it found.
- **A dispatcher's routing table is its consumers.** Each already declares the
  `iss` it expects, so C11 writes that value once: a second copy in a routing
  map would be a place for the two to disagree, and a YAML key cannot be an env
  reference the way a tenant's issuer usually is.
- **A receiver takes lists and a sender takes one.** `consumers.*.jwe` names
  keys and two allowlists because it has to accept whatever its senders are
  still using; `issuers.*.jwe` names one key and one algorithm of each kind,
  because a sender picks. Rotation is that asymmetry: the receiving side grows
  its list first, the sending side changes one name afterwards.

---

## 5. Service wiring (DI)

`config/services.yaml` holds only what exists regardless of configuration — the
clock. Everything below is registered from `loadExtension()`, per key, issuer,
consumer and command:

- `medzuch_jwt.key.<name>` and `medzuch_jwt.key.<name>.signing` /
  `.verification` — factory services building `Key` objects from each
  configured source, with the halves as separate ids so the JWKS publisher can
  only ever be handed a public one.
- `medzuch_jwt.remote_jwks.<entry>` — the `RemoteJwksResolver` for one
  `remote_jwks` entry, cache and refresh window included, and the id the error
  message for an undefined set points at. Keyed by the entry, so two consumers
  of one issuer share it.
- `medzuch_jwt.jwk_set.<consumer>` — the local `JwkSet` a consumer verifies
  against, registered only where it has local keys.
- `medzuch_jwt.resolver.<consumer>` — the `CompositeResolver`, and only that:
  registered where a consumer has both local keys and a remote set, local first
  (K6). A consumer with one or the other is handed that one directly.
- `medzuch_jwt.consumer.<name>` — the library consumer built via a static
  factory (`AccessTokenProfile::consumer(...)` etc.).
- `medzuch_jwt.handler.<name>` — our `AccessTokenHandlerInterface`
  implementation wrapping the consumer plus policy (denylist, audience policy,
  user mode). Referenced from `security.yaml`.
- `medzuch_jwt.entry_point.<name>` and `medzuch_jwt.access_denied.<name>` —
  the RFC 6750 challenge and the `insufficient_scope` handler, both named by
  the firewall rather than wired into it (DEC-1).
- `medzuch_jwt.denylist.<name>` — registered where a consumer configures one,
  public so the application can revoke through it.
- `medzuch_jwt.issuer.<name>` and `medzuch_jwt.login.<name>` — token-minting
  service and the RFC 6750 login response handler, over a
  `medzuch_jwt.issuer.<name>.profile` that is the library's builder and nobody
  else's business. A `default` issuer is aliased to `AccessTokenIssuer` for
  autowiring. There is no issuer interface: one implementation with nothing to
  swap it for would be a seam nobody uses.
- `medzuch_jwt.id_token.<name>` — the OIDC relying-party verifier, and
  `medzuch_jwt.id_token_issuer.<name>` the provider that mints what one
  verifies (I6). Both aliased for autowiring by argument name.
- `medzuch_jwt.jwks.key_set` and `medzuch_jwt.jwks_controller` — the published
  set and the action that serves it, registered only where `jwks.keys` names
  keys. The command that dumps the same set is registered on the same
  condition.
- `medzuch_jwt.token_extractor.<name>`, `medzuch_jwt.scope_voter`,
  `medzuch_jwt.scope_expression_provider`, `medzuch_jwt.command.*` — the
  firewall names the extractor; the voter and the expression provider are
  tagged; the commands are registered where what they operate on exists.
- `medzuch_jwt.clock` — alias to a PSR-20 clock; defaults to the library's
  `SystemClock`, swappable to `FrozenClock` in tests.
- User resolvers and role mapping are **inline** services inside the handler
  they belong to, not named ids: one consumer's resolver is nobody else's
  collaborator, and a name would invite it to be reused as one.
- The `logger` key names a PSR-3 service the *application* registers (a `jwt`
  Monolog channel, usually). The bundle registers no logger of its own.
- Autoconfiguration tag: `medzuch_jwt.token_claim_provider` (I3), applied by
  `registerForAutoconfiguration(TokenClaimProviderInterface::class)`. It is the
  only one. A denylist (C9) is a service the consumer names in
  `denylist.service`, not a tagged one, and there is no tag for token
  extractors either: a custom one is a service the firewall names in
  `token_extractors`, and a tag would add a second way to do what Symfony
  already does.
- Cross-reference validation (unknown key name, key/algorithm mismatch, an
  allowed algorithm with no key behind it, a JWKS entry with no public half or
  a symmetric one) happens in `loadExtension()` as the services are registered,
  rather than in a compiler pass: every one of those questions is answered by
  this bundle's own configuration, and asking it where it is read gives the
  clearest message.
- The bundle has two compiler passes, and both exist because their question
  belongs to another extension. `CollectVerdictsPass` asks whether a profiler
  wants collecting for; `CheckConfiguredServicesPass` asks whether the services
  the configuration names — `clock`, `logger`, an HTTP client, a cache, a
  denylist, a user factory — exist at all, which is not knowable until every
  extension has run. Symfony refuses a *referenced* service that is missing on
  its own, so what the pass adds is the ids nothing happens to reference (a
  `logger` with no consumer configured) and a message naming the configuration
  key rather than the service id behind it (issue #3).

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
2. Add both halves to `keys` with a new kid
3. Add the public half to the consumer's `keys` and to `jwks.keys`
   → deploy: both keys are accepted and published, nothing is signed with the new one yet
4. Point `issuers.<name>.key` at the new private half
   → deploy: new tokens carry the new kid, tokens minted a minute ago still verify
5. After the longest ttl has elapsed, drop the old key from `keys`, `jwks` and the consumer
```

---

## 7. Phased roadmap

- **Phase 0 — Skeleton.** `AbstractBundle`, composer (`type: symfony-bundle`,
  requires `medzuch/jwt-php ^1.2` + `symfony/security-bundle`), config tree
  shell, CI reusing the library's Docker QA gates (cs-fixer, PHPStan L9,
  PHPUnit) across the DEC-2 version matrix, a functional test kernel.
  *(Shipped in v0.1.0.)*
- **Phase 1 — MVP (v0.1).** T1 items: named `keys`/`issuers`/`consumers` with
  one entry each, HMAC key from env, `AccessTokenHandler` + native firewall
  wiring, `AccessTokenIssuer`, login success handler (I5 — listed under Phase 4
  in earlier drafts, but it is what makes the MVP usable without hand-writing a
  controller), `provider` user mode, PSR-3 logging, compile-time config
  validation. Functional test proving issue → request → authenticated
  controller. *(Shipped in v0.1.0; C3's `claims`/`custom` modes and C10's
  `max_token_age` are the T2 half and stay in Phase 4.)*
- **Phase 2 — Keys & rotation (v0.2).** K1–K4, K9: PEM/JWK sources, named keys,
  `kid` selection, active/accepted split, JWKS publisher, `jwt:key:generate`,
  RS256/ES256/EdDSA support end to end. *(Shipped in v0.2.0. The active/accepted split
  needed no `active` flag: an issuer names one key and a consumer names several,
  which is the same thing said once instead of twice. K1's JWKS-file source is
  deliberately not there — see the row — and Symfony Secrets need no source of
  their own, since a secret reaches `hmac` as an env reference either way.)*
- **Phase 3 — Federation (v0.3).** K5–K6, C6, C14: remote JWKS with cache and
  fallback, ID-token consumer, OIDC-RP quickstart, audience lists. *(Shipped in
  v0.3.0. The build-time check that every allowed algorithm
  has a key behind it is suspended for a consumer with a remote set — the issuer
  publishes its algorithms at runtime, which is the "own reading of satisfied"
  the K5 row always implied.)*
- **Phase 4 — DX & hardening (v1.0).** C4, C5, C7, C9, C10's max age,
  C13, I2–I4, O1–O5, D1–D5, D7, K9: user modes, role mapping, extractors, denylist, scope
  voter, claim providers, events, profiler panel, console commands, test
  helpers, documentation, `WWW-Authenticate` handling, configurable log levels,
  and key material held to where it may appear. **1.0 = the T1+T2 set,
  documented, with a BC policy.** *(Shipped in v1.0.0. There was no v0.4: the
  phase ran long enough that stamping an interim minor would have promised
  nothing the BC policy did not already say better.)*
- **Phase 5+ — Standards-track (post-1.0).** §3.6, together with the T3 rows
  that live elsewhere in §3 — C11's multi-tenant issuer dispatch (§3.1) and
  D6's Flex recipe (§3.5): DPoP, mTLS binding, token exchange, introspection
  fallback, JWE/nested tokens, SET issue/consume, discovery documents.
  *(Shipped in v1.1.0: the pairs whose library half already existed — C8/I7,
  C12/I8, I6 — and the rows that needed nothing from it: K7, K8, C11, and C15,
  which turned out to be firewall configuration rather than code. I9 followed,
  as the contract §8.1 always meant it to be rather than as storage. Still
  open: DPoP, mTLS binding, token exchange and introspection, all of which
  begin as library work; and D6, whose recipe has to be submitted to
  `symfony/recipes-contrib` rather than landing here.)*
  *(K7 landed first, and the order is worth recording: what the library already
  carries decides what is a bundle-sized change. JWE and SET are whole
  implementations in `medzuch/jwt-php` already, so C12/I8 and C8/I7 are wiring;
  K7 needed nothing from it at all. DPoP and mTLS are the opposite — `cnf.jkt`
  needs RFC 7638 thumbprints and `cnf.x5t#S256` needs certificate hashing,
  neither of which exists there yet, so both begin as library work rather than
  as a branch here.)*

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
   *(Shipped in Phase 5: `RefreshTokenStoreInterface` and the generator that
   fills it. The line held — the only executable code is `random_bytes()`, a
   SHA-256 and a lifetime check, and the one implementation in this repository
   is a test double.)*
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

## 9. Decisions

The five questions this plan carried through v0.4 are settled. Each entry
records the decision, why it went that way, and what would reopen it.
Decisions are referenced as `DEC-n`; the `D`-numbered rows in §3.5 are the
unrelated developer-experience catalogue.

**DEC-1 — Firewall wiring: the native `access_token` block only. No `medzuch_jwt:`
firewall shorthand.** The shorthand would save one line of YAML and cost an
`AuthenticatorFactoryInterface` implementation — a security-bundle extension
point to keep working across three Symfony majors — plus a second, divergent
way to configure the same handler. Everything the native block already offers
(token extractors, `realm`, success/failure handlers, and whatever Symfony adds
next) comes free precisely by not owning that layer; a shorthand would have to
be re-taught each addition or quietly fall behind it. The DX gap is closed with
documentation (D7) and a Flex recipe (D6) instead, neither of which forks the
security configuration surface. *Reopens if* a feature cannot be expressed
through a token handler at all: DPoP (§3.6) needs a second header plus proof
replay checks. That gets its own, explicitly named authenticator — not a
shorthand alias for the existing one.

**Correction (Phase 5).** This paragraph also named C15 — "authenticate if a
token is present, don't 401 if it isn't" — as a second reason to reopen. It was
wrong about what C15 needs. `AccessTokenAuthenticator::supports()` returns
`false` when the extractor finds nothing, so Symfony *already* declines rather
than fails an anonymous request: what refuses one on a guarded path is the
access rule, and exempting the path is the entire capability. C15 landed as
documentation and tests over configuration that already worked, with no
authenticator and no bundle code. DPoP remains the only live reason to reopen.

**DEC-2 — Supported versions: PHP `~8.3.0 || ~8.4.0`, Symfony `^6.4 || ^7.4 || ^8.0`.**
v0.4's "6.4 LTS and 7.x" was written before Symfony 7.4 LTS and 8.0 shipped.
7.0–7.3 have all reached end of life, so requiring `^7.4` excludes only
unmaintained minors; 6.4 stays because its security window runs to November
2027 and it is where most deployed applications sit. The APIs this bundle
touches — `AbstractBundle` (6.1+), the `access_token` authenticator (6.2+),
`AccessTokenHandlerInterface`, `UserBadge` — are unchanged across all three
majors, so the cost is CI matrix breadth, not conditional code. Matrix: 6.4 on
PHP 8.3 twice — once resolved highest, once with `--prefer-lowest`, which is
the floor as an application installs it — 7.4 on 8.3 and 8.4, and 8.x on 8.4 as
`8.*` rather than a pinned minor (Symfony 8 requires PHP 8.4, and the library's
ceiling is 8.4). The LTS legs can be pinned because an LTS line does not move;
the 8 leg cannot, or a minor would reach an application before it reaches CI.
If a version-conditional branch ever becomes necessary in `src/`, that is the
signal to raise the floor rather than to add the branch.

*Reviewed 2026-08-20:* 6.4 stays until **November 2026**, when it leaves active
support, and the floor rises to `^7.4` in the release after that. It is no
consumer's requirement — the only application on this library pins `7.4.*` — so
what holds it here is reach, and reach is what expires with the support window.
Two things to know before doing it: `treatPhpDocTypesAsCertain` stays off either
way, since that conflict is Symfony 8 against 7.4 as well, and one of the two
6.4 legs is the `--prefer-lowest` one, which has to move to the new floor
rather than disappear with 6.4.

**DEC-3 — Revocation: `TokenDenylistInterface`, a `NullDenylist` default and a
PSR-16 implementation in-tree; no Doctrine entity, now or later.** A denylist
entry is keyed on `jti` and only has to outlive the token carrying it, so its
natural lifetime is that token's remaining TTL — which is exactly what
`set($jti, true, $ttl)` expresses and what a relational table does not. A SQL
store would add a schema, a migration and a garbage-collection command to a
security bundle in exchange for durability a short-lived denylist does not
need. `psr/simple-cache` stays an optional dependency: the implementation is
registered only when a `denylist` is configured. *Reopens if* an application
needs revocation to survive a cache flush — but that is a durability
requirement, and it belongs in an app-owned implementation of the interface (or
a separate `medzuch/jwt-bundle-doctrine`), not on the default path.

*Shipped without the `NullDenylist` this called for.* An unconfigured consumer
holds no denylist and asks nothing, which is the same default with one fewer
moving part: a service that always answered "not revoked" would be a lookup per
request buying nothing, and would appear in `debug:container` as revocation an
application never asked for.

**DEC-4 — Upstream gaps: closed. The bundle requires `medzuch/jwt-php ^1.2.1`.** All
four blockers v0.4 recorded were fixed upstream, backward compatibly, in 1.1.0:
leeway on all three profile consumers, `string|non-empty-list<string>`
audiences on `AccessTokenProfile::consumer()`, `?string $passphrase` on
`RsaPrivateKey::fromPem()` and `EcPrivateKey::fromPem()`, and
`"php": "~8.3.0 || ~8.4.0"`. 1.2.0 added the `expectAudience()`/`expectIssuer()`
shape backstop that §4 now normalises for, and 1.2.1 fixed
`MediaType::equivalent()`, which decides both the `cty` of an encrypted token
(C12) and the `typ` an ID token must not carry (I6) — the floor names that
patch because both checks were wrong without it. The library is on Packagist,
so it is an ordinary dependency rather than a VCS repository.

*Reversed for `max_token_age` (C10), which this decision sent upstream and
Phase 4 built here.* The reasoning was that comparing `iat` against a clock is
temporal claim validation of the same family as `exp`/`nbf`, so it belonged
with them. That reads the check as a claim rule, and it is not one: `exp` is
the issuer's statement about a lifetime, while a maximum age is **this
application's policy about what it will accept** — two applications verifying
the same token are entitled to different answers, which is exactly what a
profile must not encode. The two costs the decision named did not appear
either. The clock and leeway are constructor arguments the handler was already
being given for other reasons, and O4 never reads a `RejectionReason` at all:
Symfony maps every token failure to `invalid_token`, so nothing about
`WWW-Authenticate` had to be special-cased. The refusal carries its own
`too_old` instead, which is the distinction an operator needs and the one an
upstream `withMaxAge()` could not have made.

**DEC-5 — `kid`: explicit, never derived from key material, and mandatory once two
keys share an algorithm.** Deriving a `kid` by hashing an HMAC secret would
publish a value computed from that secret in every token header — an offline
check for guessed secrets, bought for the convenience of not typing a name.
Deriving it from the config entry's name instead is safe, but writes a
bundle-internal identifier into the wire format. So `kid` is configuration: it
stays optional for the single-key case (most HS256 deployments, with no
rotation story to support), and the build-time validation (D8) **requires** it as soon
as a key set holds two keys bound to the same algorithm. Without it the
library's `StaticJwkSetResolver` resolves a `kid`-less header to *the first* key
bound to that `alg` and throws if that one does not verify — it does not try
the rest, by design ("a token that claims a specific key must be verified with
that key or not at all"). A `kid`-less rotation is therefore a hard cutover
that invalidates every token still in flight; refusing that configuration at
container build beats discovering it mid-rotation.

**DEC-6 — the JWKS route belongs to the application.** Deferred through v0.1.0,
settled with K4: the bundle registers `medzuch_jwt.jwks_controller` and no route
at all. Where a JWK Set lives — under `/.well-known/`, behind a prefix, on a
separate host, or nowhere because this deployment publishes nothing — is a
routing decision, and routing is the application's. Shipping a route file would
have needed a `path` key and an `enabled` key to answer questions the
application's own routing already answers, and an imported route file that
disagrees with `enabled` is a failure mode with no upside. The cost is three
lines of YAML in the application, which is what any other controller costs.

**DEC-7 — a JWK and the configuration pointing at it must agree.** A JWK states
its own `alg`, `kid` and `use`; the configuration states them too, because
`keys.<name>.algorithm` and `.kid` are what the container is built from — which
algorithms a consumer can verify (K1), which two keys a token could not tell
apart (DEC-5), whether a key has a half to publish (K4). The document is read
when the key is first built (K9), long after those answers were given. So the
configuration is authoritative for what the bundle reasons about, the document
is authoritative for the material, and where the document is silent the
configuration fills it in; a disagreement is refused, naming both readings.
The rejected alternative was letting the document win: it would make every
build-time answer describe a key other than the one signing, and it would let a
`kid` nobody configured appear in a published JWK Set. Reopen if a key source
arrives whose documents cannot be re-stated in configuration — a remote JWKS
(K5) is exactly that, and it is resolved at runtime for the same reason.

**DEC-8 — an ID token gets a service, not a firewall authenticator.** C6 could
have been a second `AccessTokenHandlerInterface`, and that is the shape a
relying party asks for when they have not thought it through: point a firewall
at the provider, accept ID tokens as bearer credentials, done. It is also
exactly the confusion RFC 9068 exists to end — an ID token attests that someone
authenticated *to the client that requested it*, on a schedule and with an
audience that has nothing to do with an API call, so a token minted for a
browser session would authorise a machine one. The bundle therefore registers
`medzuch_jwt.id_token.<name>` (an `IdTokenVerifier`, public and injectable by
argument name) and no handler: there is a service at the point where an ID
token legitimately arrives, and nothing that fits into `access_token`. I6 added
the other end — `medzuch_jwt.id_token_issuer.<name>`, called from a token
endpoint — and the same reasoning shapes it: a service where the flow is, and
the verifier refuses a token typed `at+jwt`, so a deployment holding both ends
cannot have one accepted as the other in either direction. The
`nonce` is an argument rather than configuration for the same class of reason —
it belongs to one authentication request, and a value fixed at deploy is not a
nonce. *Reopens if* a deployment appears where an ID token is the only
credential available at an API boundary; the answer then is still not a handler
but an explicit exchange, and the reasoning above is what it has to beat.

---

*Library API touchpoints (verified against `medzuch/jwt-php` v1.2.1 `src/`):*
*`AccessTokenProfile::issuer()/consumer()` (audience list, leeway), `IdTokenProfile`,*
*`SetProfile`,*
*`ProfileConsumer::parse(string): ClaimsSet` (throws `JwtException`),*
*`AccessTokenBuilder` (`subject/audience/scope/clientId/expiresIn/withClaim/build`),*
*`ClaimsSet` accessors, `JwkSet`/`JwkParser`, `KeyResolver` with*
*`StaticJwkSetResolver` / `RemoteJwksResolver` / `CompositeResolver`,*
*`HmacKey`/`RsaPrivateKey::fromPem($pem, $passphrase)`/`EcPrivateKey`/`OkpPrivateKey`,*
*`SigningAlgorithm` implementations (`Hs256`…`Es512`, `EdDsa`),*
*`MediaType`, `NestedJwtBuilder`/`NestedJwtParser`, PSR-20 `SystemClock`/`FrozenClock`,*
*PSR-3 logging via `SecurityLog`/`LogLevels`.*
