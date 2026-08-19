# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Configuration keys under `medzuch_jwt:` are public API: a rename or removal is
a breaking change and is recorded here with its deprecation path, the same way
a class or method signature would be.

## [Unreleased]

Nothing released yet — the package is finishing Phase 1 (MVP). See
[`docs/plan.md`](docs/plan.md) §7 for the roadmap.

### Added

- **A README that gets you running**, with a quickstart per role — verify on a
  resource server, issue on login, both at once — plus how keys are configured
  and what the bundle refuses to boot with. Every `medzuch_jwt` example in it is
  compiled into a real container by the test suite, so a renamed configuration
  key cannot leave the quickstart telling newcomers to write something that no
  longer works. The exhaustive reference is not duplicated by hand:
  `config:dump-reference medzuch_jwt` generates it from the bundle.
- **Named `issuers`, a token issuer, and an RFC 6750 login response.**
  `medzuch_jwt.issuer.<name>` mints RFC 9068 access tokens — the profile
  supplies `iss`, `iat`, `jti` and the `at+jwt` header, configuration supplies
  the audience, client id, TTL and any static claims, and the caller supplies
  the subject, scopes and per-token claims. The signing algorithm is **not**
  configured on the issuer: it comes from the key, which is bound to exactly
  one, so restating it could only ever disagree. `medzuch_jwt.login.<name>`
  plugs into any authenticator's `success_handler` (`json_login`, `form_login`)
  and answers a successful login with `access_token` / `token_type` /
  `expires_in`, under `Cache-Control: no-store` (RFC 6749 §5.1 — a cached token
  response is a disclosed token). An issuer named `default` is aliased for
  autowiring. A static claim naming one of the registered claims (`iss`, `sub`,
  `aud`, `exp`, `nbf`, `iat`, `jti`) is refused at container build, where every
  other misconfiguration in this bundle is refused, rather than throwing on the
  first token minted.
- **Named `keys` and `consumers`, and a working token handler.** A firewall can
  now point `token_handler` at `medzuch_jwt.handler.<name>` and get RFC 9068
  access-token verification through the library's access-token profile: issuer,
  audience, algorithm allowlist, `typ` pinning and the required-claim set, with
  optional clock leeway bounded by the library's own ceiling. HMAC keys come
  from configuration as a secret — an env reference, so no key material reaches
  a container parameter that `debug:container` would print.
- **Wiring mistakes fail at container build, not at the first request.** All of
  these are refused with a message naming the configuration key at fault: a
  consumer naming a key that does not exist; an allowed algorithm with no key
  behind it, so a token using it could never be verified; two keys a token
  cannot tell apart — sharing a `kid`, or sharing an algorithm with no `kid` at
  all (DEC-5: resolution is first-match-wins in both directions and never falls
  back, so the second key verifies nothing and rotation silently invalidates
  every token in flight); an empty `kid`; a YAML map where a sequence is
  expected; leeway above the library's ceiling; and unknown algorithm names.
- **Bundle-internal service configuration is YAML** (`config/services.yaml`),
  matching the application-facing side. This adds `symfony/yaml` to `require`.
- **Bundle skeleton.** `MedzuchJwtBundle` on `AbstractBundle`, which derives
  the `medzuch_jwt` configuration root and the `Medzuch\JwtBundle\` namespace
  from the class name. Both are public API from this point on.
- **`medzuch_jwt.clock`.** The only configuration key Phase 0 carries: the
  service id of a PSR-20 clock, defaulting to the library's `SystemClock`. A
  configured id replaces the default through an alias, so everything
  time-dependent added later resolves one id and an application can freeze time
  in its tests without the bundle growing a test-only branch.
- **Functional test kernel** (`tests/Functional/App/TestKernel.php`) that
  compiles a real container, keyed by the configuration under test so two
  cases cannot share a compiled container. Covers booting with no
  configuration at all, the clock override resolving to the application's own
  service, and an unknown configuration key failing at container build.
- **QA toolchain**, mirroring `medzuch/jwt-php` so moving between the two
  repositories costs nothing: php-cs-fixer (same rule set), PHPStan level 9
  with strict rules, PHPUnit, a Docker dev image on the PHP floor with an
  opt-in 8.4 profile, and a `Makefile` wrapping both.
- **CI across the DEC-2 support window** — Symfony 6.4 / 7.4 / 8.0 against PHP
  8.3 and 8.4, with `symfony/flex` pinning each leg to its Symfony line. Every
  action is pinned to a commit SHA, which the repository enforces. A weekly
  scheduled run re-resolves dependencies so upstream drift reports itself
  instead of reddening an unrelated pull request.
- Repository policy: contribution and security guidelines, PR template,
  Dependabot configuration for GitHub Actions, and branch/tag protection
  rulesets (`main` requires a pull request and merge commits; `v*` tags cannot
  be moved or deleted).
