# medzuch/jwt-bundle — Design Plan (v0.3)

> **Goal.** A Symfony bundle that wires our standalone `medzuch/jwt-php` library
> into a Symfony application so a project can (a) **issue** secure JWTs
> (RFC 9068 access tokens, OIDC ID tokens, custom JWS/JWE) and (b) **authenticate**
> incoming requests against those tokens using Symfony's native Security stack.
>
> This document starts general (what a bundle is, how Symfony Security works) and
> narrows to a concrete file/config/service design plus a phased roadmap. Still a
> living draft — no bundle code exists yet (Phase 0 in §7 below) — but it now
> lives in this repo rather than as an untracked file inside `jwt-php`.
>
> **v0.2 change:** scope trimmed against a real first consumer,
> [`home-budget`](../../home-budget) (Budget Ecosystem — Symfony 7.4, PHP 8.3+).
> Its ADRs (004, 009) and `docs/security.md` already lock in the concrete shape
> of auth the bundle needs to support. See §8 for what that resolved. Anything
> the plan previously speculated about that home-budget *doesn't* need has been
> cut or pushed to "later" rather than built speculatively.
>
> **v0.3 change:** moved out of `jwt-php`'s `docs/` into this dedicated repo,
> per the roadmap this document itself proposed. home-budget's
> [ADR-010](../../home-budget/docs/adr/010-medzuch-jwt-bundle-over-lexik.md)
> now formally records the decision to use this bundle instead of
> LexikJWTAuthenticationBundle; this document is the design referenced from
> there, and from `home-budget`'s phase 0/1 task lists.

---

## 0. Guiding principles

1. **Thin adapter, not a re-implementation.** All crypto/claim logic stays in
   `medzuch/jwt-php`. The bundle only does: DI wiring, configuration, and
   implementing Symfony's contracts (mainly `AccessTokenHandlerInterface`).
2. **Native integration first.** Prefer Symfony's built-in `access_token`
   authenticator + `AccessTokenHandlerInterface` over a bespoke authenticator.
   We only write a custom authenticator if the native one can't express something.
3. **Secure-by-default.** Stateless firewall, explicit allowed algorithms (no
   `alg` confusion), required-claim enforcement, `typ` pinning — all inherited
   from the library's profiles (`AccessTokenProfile`, `IdTokenProfile`).
4. **Framework-version target.** Symfony **7.x** (7.4 confirmed by home-budget).
   PHP 8.3+ to match the library.
5. **Build for the first real consumer, not a hypothetical third party.** Until
   there's a second consuming app, features that only matter for multi-tenant /
   published-package use (key rotation, scopes-as-roles, Flex recipe) stay out
   of scope rather than being spec'd in advance. See §8.

---

## 1. Background — What a Symfony bundle is (modern style)

A bundle is reusable, shareable code (services, config, contracts) packaged for
multiple Symfony apps. In modern Symfony (6.4 / 7.x) the recommended base is
`AbstractBundle`, which collapses the old `Bundle` + `Extension` + `Configuration`
ceremony into one class.

**Minimum anatomy of a modern bundle:**

```
jwt-bundle/
├── composer.json                 # type: symfony-bundle, PSR-4, requires medzuch/jwt-php
├── src/
│   ├── MedzuchJwtBundle.php       # extends AbstractBundle; config() + loadExtension()
│   ├── DependencyInjection/       # (optional if not using AbstractBundle inline config)
│   ├── Security/                  # AccessTokenHandler, user provider
│   ├── Issuer/                    # token-minting services
│   └── ...
├── config/
│   └── services.php               # service definitions (loaded by the bundle)
└── tests/
```

**Key facts that shape our design:**

- **Registration.** Apps add `Medzuch\JwtBundle\MedzuchJwtBundle::class => ['all' => true]`
  to `config/bundles.php`. (No Flex recipe for now — see §8 — so this is manual.)
- **`AbstractBundle::configure(DefinitionConfigurator $definition)`** defines the
  config tree (replaces a separate `Configuration` class for simple bundles).
- **`AbstractBundle::loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder)`**
  reads validated config and registers/parameterizes services.
- **Service config** lives in `config/services.php` (PHP config, for type-safety
  and IDE support) and is imported from `loadExtension()`.
- **Naming.** Class `MedzuchJwtBundle`, config root key `medzuch_jwt`, composer
  name `medzuch/jwt-bundle`, namespace `Medzuch\JwtBundle\`.

---

## 2. Background — Symfony Security, and where JWT plugs in

Symfony Security pipeline (relevant slice):

```
Request
  → Firewall (pattern match; stateless for APIs)
    → Authenticator (decides "who are you?")
      → Passport(UserBadge + badges)
        → User Provider (loads/refreshes the user)
          → CheckPassportEvent (extra validation)
            → Authorization (access_control / #[IsGranted] / Voters)
              → Controller
```

### 2.1 The native fit: `access_token` authenticator + `AccessTokenHandlerInterface`

Symfony ships an **`AccessTokenAuthenticator`** for bearer-token (stateless) auth.
You don't write the authenticator — you configure it and provide a **token handler**:

```yaml
# security.yaml (in the consuming app)
security:
  firewalls:
    api:
      pattern: ^/api
      stateless: true
      access_token:
        token_handler: medzuch_jwt.security.access_token_handler   # our service
```

The handler implements one method:

```php
interface AccessTokenHandlerInterface
{
    public function getUserBadgeFrom(string $accessToken): UserBadge;
}
```

**This is the single most important integration point.** Our handler will:

1. Take the raw compact bearer string.
2. Validate it via `AccessTokenProfile::consumer(...)->parse($token)` →
   returns a validated `ClaimsSet`, or throws a `JwtException`.
3. On success, return `UserBadge($claims->subject())` — the app's own user
   provider loads the `User` entity by that identifier (home-budget's model;
   see §3.1 below). No claims-only user object; the badge just carries `sub`.
4. On failure, throw `BadCredentialsException` (Symfony maps it to 401).

By default the native authenticator reads the token from the
`Authorization: Bearer <token>` header (configurable: header/query/body/custom
`token_extractors`).

### 2.2 Turning a token into a `User`: DB-backed only

home-budget's `HouseholdVoter` authorizes against the database on every
request — household membership and roles are deliberately **not** encoded in
the JWT (ADR-009), to avoid stale-token privilege bugs. So the bundle supports
**one** user-resolution mode: `UserBadge($claims->subject())` + the app's own
Doctrine user provider loads the `User` entity by `sub`. There is no
claims-only/stateless user mode and no claim→role mapper — the JWT carries
identity only; authorization is always a DB lookup downstream. (A previous
draft of this plan proposed a stateless-vs-provider toggle and a
`scope`/`roles`/`groups`-claim mapper; both are cut — home-budget has no use
for either, and building them speculatively isn't worth the maintenance.)

---

## 3. What the bundle actually provides

### 3.1 Consumer side (resource server) — *authenticate incoming requests*

| Piece | Backed by |
|---|---|
| `AccessTokenHandler` (impl. `AccessTokenHandlerInterface`) | `AccessTokenProfile::consumer()` |
| App's own Doctrine user provider, loading `User` by `sub` | library `ClaimsSet::subject()` |
| Optional ID-token handler variant | `IdTokenProfile::consumer()` (not needed by home-budget yet — no OIDC) |

Dropped from the original draft: claims-only `JwtUser`, claim→role mapper,
`ScopeVoter`. home-budget authorizes via `HouseholdVoter` against the DB, not
JWT claims — there's nothing for a scope voter to do here.

### 3.2 Issuer side (authorization server / login) — *mint tokens*

| Piece | Backed by |
|---|---|
| `AccessTokenIssuer` service (`issue(sub, aud, scopes, ttl): string`) | `AccessTokenProfile::issuer()` |
| Optional `JsonLoginAuthenticator` success handler that returns `{access_token: ...}` | Symfony + issuer |

Dropped: `IdTokenIssuer` (no OIDC use case yet), JWKS-publisher endpoint (no
RS256/rotation yet — see §8).

**Not the bundle's job:** refresh-token issuance, storage, rotation, or
revocation. home-budget's refresh tokens are opaque random strings hashed in
its own `refresh_tokens` table (ADR-009) — not JWTs at all. That's app-level
Doctrine/business logic; the bundle only ever touches the short-lived access
JWT.

---

## 4. Configuration design (`medzuch_jwt`)

Trimmed to what's actually used — one key, symmetric, both roles enabled:

```yaml
# config/packages/medzuch_jwt.yaml
medzuch_jwt:
  key:
    hmac: '%env(JWT_SECRET)%'        # HS256, MVP. RS256/named keys: see §8, not yet.

  consumer:
    issuer: '%env(APP_URL)%'          # home-budget is issuer and consumer of its own tokens
    allowed_algorithms: ['HS256']
    leeway: 0

  issuer:
    issuer: '%env(APP_URL)%'
    algorithm: HS256
    access_token:
      ttl: 900                        # 15 min, matches ADR-009 / security.md
```

Design notes:
- **One key, symmetric.** No `keys.*` map, no `kid` selection, no PEM/JWKS
  loading — those only earn their cost once there's key rotation or a second
  service verifying home-budget's tokens. Cut from the original draft's §4.
- **No `user.mode`/`roles_claim` block** — see §2.2.
- **Consumer and issuer both always enabled** — home-budget is both; there's
  no resource-server-only or auth-server-only deployment to support.
- `allowed_algorithms` maps to the library's `SigningAlgorithm` enum (validated).

---

## 5. Service wiring (DI)

`config/services.php`, registered from `loadExtension()`:

- `medzuch_jwt.key` — factory service building the `HmacKey` from `JWT_SECRET`.
- `medzuch_jwt.consumer` — `AccessTokenProfile::consumer(...)` built via a
  static-factory service definition; depends on the key service + config.
- `medzuch_jwt.security.access_token_handler` — our `AccessTokenHandler`
  (implements `AccessTokenHandlerInterface`), depends on the consumer.
- `medzuch_jwt.issuer.access_token` — issuer service.
- `medzuch_jwt.clock` — alias to a PSR-20 clock (`psr/clock`); default
  `Medzuch\Jwt\Primitives\SystemClock`, overridable for testing.
- `medzuch_jwt.logger` — optional PSR-3 logger passed into the profile consumer
  (the library already redacts and logs once per parse via `SecurityLog`).

Dropped: `medzuch_jwt.key.<name>` multi-key map, `JwtUserProvider`/`ScopeVoter`
autoconfiguration tags — no longer needed per §2.2/§3.

---

## 6. End-to-end flows

### 6.1 Login → issue (issuer side)

```
POST /api/auth/login  →  app verifies credentials, checks email_verified_at
  → AccessTokenIssuer::issue(sub: $user->getId(), ttl: 900)
      └─ AccessTokenProfile::issuer($iss, new Hs256(), $hmacKey)->issue()
           ->subject($user->getId())->expiresIn(...)->sign()
  → app mints its own opaque refresh token (own table, own logic — not the bundle)
  → JSON { "accessToken": "<compact JWS>", "user": {...} }
    + Set-Cookie: refreshToken=... (app-level, not the bundle)
```

### 6.2 Request → authenticate (consumer side)

```
GET /api/...  Authorization: Bearer <token>
  → stateless firewall, access_token authenticator
    → AccessTokenHandler::getUserBadgeFrom($token)
        └─ AccessTokenProfile::consumer(...)->parse($token): ClaimsSet  (or throws)
        → UserBadge($claims->subject())
    → app's Doctrine user provider loads User by id
  → HouseholdVoter checks membership from the DB (not from the token)
  → controller
```

This matches home-budget's `docs/architecture.md` data-flow example almost
exactly, with `AccessTokenHandler` implementing the step that
[ADR-010](../../home-budget/docs/adr/010-medzuch-jwt-bundle-over-lexik.md)
formally assigned to this bundle instead of LexikJWTAuthenticationBundle.

---

## 7. Phased roadmap

- **Phase 0 — Skeleton.** `AbstractBundle`, composer (`type: symfony-bundle`,
  require `medzuch/jwt-php`, `symfony/security-bundle`), config tree from §4,
  CI reusing our Docker QA gates (cs-fixer, phpstan L9, phpunit). *(Not
  started — this repo currently has no bundle code, only this plan.)*
- **Phase 1 — Consumer + issuer MVP (combined).** `AccessTokenHandler`,
  native `access_token` firewall wiring, `AccessTokenIssuer`. Functional test
  with a real Symfony test kernel. This is the phase that unblocks
  home-budget's Phase 1 (identity-and-households) — see §8.
- **Phase 2 — DX & release.** Docs, changelog, tag `v0.1.0`. Skip the Flex
  recipe (§8) unless a second consuming app shows up.
- **(Later, only if/when needed)** Named multi-key + `kid` rotation, PEM/JWKS
  key sources, RS256 (home-budget's own security.md already flags this as "if
  we extract an identity service"), `IdTokenProfile` wiring (OIDC), a JWKS
  publisher endpoint, remote JWKS consumption once the library's
  `RemoteJwksResolver` lands.

Dropped entirely (not just deferred) unless a concrete future need appears:
`ScopeVoter`, claim→role mapping, stateless claims-only user mode, provider-
backed vs stateless toggle, Flex recipe/`symfony/recipes-contrib` publish.

---

## 8. What got resolved by reading home-budget's docs (was: "open questions")

The original draft ended with 7 open questions. Reading home-budget's ADR-004,
ADR-009, `security.md`, `tech-stack.md`, and `phases/01-identity-and-households.md`
answered all of them concretely:

1. **Consumer vs issuer first?** — False choice. home-budget is both; Phase 1
   above does both together.
2. **User model default?** — DB-backed only (§2.2). No stateless mode needed.
3. **JWE / nested tokens in scope?** — No. HS256 compact JWS, one app signs
   and verifies its own tokens; no third party to hide claims from.
4. **Refresh tokens / revocation — bundle concern?** — No. home-budget's
   refresh tokens are opaque, DB-stored, single-use-with-rotation (ADR-009) —
   entirely outside the JWT/bundle boundary.
5. **Flex recipe?** — Skipped until a second consuming app exists.
6. **Config format — PHP vs YAML?** — YAML for the app-facing
   `config/packages/medzuch_jwt.yaml` (matches every other Symfony bundle
   home-budget already configures that way); PHP for the bundle's own
   internal `config/services.php`, per §1.
7. **Target versions?** — Symfony 7.4, PHP 8.3+ (home-budget's `composer.json`
   says `>=8.2`, but its own CLAUDE.md/tech-stack.md commit to 8.3+ in
   practice — matches jwt-php's requirement).

**Remaining open item, not resolved by home-budget's docs:** home-budget's own
`composer.json` currently pins `"php": ">=8.2"` while jwt-php's `composer.json`
pins `"php": "~8.3.0"` — a tilde constraint, which caps out *below* 8.4, not
just "8.3+". If home-budget or its host ever moves to PHP 8.4, jwt-php would
need that constraint loosened first. Worth a note in jwt-php's own backlog,
independent of the bundle.

---

*Library API touchpoints (verified against `src/`):*
*`AccessTokenProfile::issuer()/consumer()`, consumer*
*`->parse(string): ClaimsSet` (throws `JwtException`), `ClaimsSet::subject()`,*
*`HmacKey`, `Hs256`, PSR-20 `SystemClock`, PSR-3 logging via `SecurityLog`.*
