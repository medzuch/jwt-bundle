# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Configuration keys under `medzuch_jwt:` are public API: a rename or removal is
a breaking change and is recorded here with its deprecation path, the same way
a class or method signature would be.

## [Unreleased]

## [0.2.0] — 2026-08-20

Phase 2 of the roadmap in [`docs/plan.md`](docs/plan.md): keys stop being one
shared secret. RSA, EC and Ed25519 keys, from PEM or JWK documents, named and
rotatable without downtime; a JWK Set endpoint for the relying parties that
verify your tokens; and a command that generates any of it and prints the
configuration to paste.

**Still pre-1.0.** Configuration keys are public API and changes to them are
recorded with a deprecation path, but the surface is young enough that it
should be expected to move. No configuration key from 0.1.0 was removed or
renamed, so an application on HMAC keys upgrades by changing the constraint —
unless it named one key twice in a consumer's `keys`, which is now refused;
see **Changed**.

### Added

- **JWK key sources, and with them EdDSA.** A key entry takes `jwk_private` and/or
  `jwk_public` — a path to a JSON file or the JSON itself — beside the `pem_*` and
  `hmac` sources it already had. `EdDSA` is configured this way and no other: RFC 8037
  defines Ed25519 as a JWK and there is no PEM spelling of it to read, so a `pem_*`
  source bound to `EdDSA` is refused at container build, saying which source it takes.
  A JWK states its own `alg`, `kid` and `use` and so does the configuration pointing at
  it; what the configuration states and the document omits is filled in, and a
  disagreement is refused when the key is loaded, naming both readings. The two
  refusals that would otherwise be silent: a document carrying `d` behind `jwk_public`,
  which the JWKS endpoint would publish verbatim, and a JWK **Set** where a single key
  belongs — the document people have on hand, since it is what a JWKS endpoint serves.
- **`jwt:key:generate`.** Generates an HMAC secret, an RSA or EC keypair in PEM or JWK,
  or an Ed25519 keypair, and prints the `medzuch_jwt` block that uses it — which source
  the material belongs in, both halves, and the `kid` in place. Key paths in that block
  are anchored to `%kernel.project_dir%`, because the key is read when the key service is
  first built, in whatever working directory that process has. `--out` writes the files
  instead of printing them: into a `0700` directory, the private half `0600` and created
  before it holds anything, and neither half ever overwritten, because a key file replaced
  in place invalidates every token still in flight. A shared secret is printed as an
  environment line rather than written, since that is where the `hmac` source reads it.
  The command is registered only when `symfony/console` is installed, so a container
  without one still builds.
- **A JWK Set endpoint.** `medzuch_jwt.jwks` names the keys to publish and
  `medzuch_jwt.jwks_controller` serves them as RFC 7517 `application/jwk-set+json`,
  cacheable for a configurable time. The bundle registers **no route**: where the
  document lives is a routing decision and routing belongs to the application
  (DEC-6 in the plan). Publishing a shared secret is refused at container build —
  a symmetric key's JWK carries the secret itself, so it would hand every reader
  the key that signs, in a document that parses and returns 200. So is a key with
  no public half, one that does not exist, one named twice, and a set whose keys
  a relying party could not tell apart — the same `kid` rules a consumer's keys
  already answer to, for the same reason: the published document is the only
  thing a relying party has to resolve against. Published keys state
  `use: "sig"`, and the response carries an `ETag`, so a conditional request
  gets a 304 and `cache_max_age: 0` means revalidate rather than refetch.
- **Key rotation works without a rotation feature.** An issuer signs with one key
  while a consumer accepts several, so adding a key, accepting it, then signing
  with it rotates with no downtime — and the `kid` requirement that makes the
  overlap resolvable is already enforced. Documented as a procedure in the
  README, with a functional test that mints from the retired key and verifies it
  alongside the current one.
- **RSA and EC keys.** A key entry takes `pem_private` and/or `pem_public`
  instead of `hmac`, each of them either a path to a PEM file or the PEM
  itself — told apart by the armour, since no path begins with `-----BEGIN`.
  `pem_passphrase` opens an encrypted private key. The two halves are separate
  entries because they are separate things: only the private one signs, only
  the public one verifies, and a private key cannot stand in for its public
  half. RS256/384/512 and ES256/384/512 work end to end; `EdDSA` has no key
  source yet and says so.
- **A key's algorithm decides what material it must be given.** A shared secret
  for an RSA algorithm, a PEM for an HMAC one, both at once, or neither are all
  refused at container build, as are a passphrase with no private key to
  unlock, a consumer verifying with a private-only key, and an issuer signing
  with a public-only one.

### Changed

- **A consumer naming the same key twice is refused at container build.** It
  booted in 0.1.0: the key went into the verification set twice, and since
  resolution is first-match-wins the second copy was simply unreachable. It is
  now an error for the same reason the other key checks are — the second
  mention cannot change what verifies, so it was either a typo or a
  misunderstanding of what listing a key twice would do. The only affected
  configuration is one that already carried a redundant entry.
- **Key services answer by role**: `medzuch_jwt.key.<name>.signing` and
  `medzuch_jwt.key.<name>.verification`, so both sides read the same at the call
  site. For a shared secret both are aliases to `medzuch_jwt.key.<name>`, which
  a symmetric key genuinely is; for a keypair only the half that was configured
  exists. Symmetric keys are both halves at once, asymmetric ones are not, and
  the container should not pretend otherwise.
- **The `kid` ambiguity check moved from the whole configuration to each
  consumer's key set**, which is where the ambiguity actually lives — the
  resolver only ever sees the keys of the consumer doing the verifying. The
  global check rejected the most ordinary asymmetric setup there is: a private
  entry and a public entry that are two halves of one keypair, sharing an
  algorithm and a `kid` precisely because they are the same key.

## [0.1.0] — 2026-08-19

First release: the MVP of the design in [`docs/plan.md`](docs/plan.md), which is
Phases 0 and 1 of its roadmap. An application can mint an access token on login
and authenticate the next request with it, through Symfony's own `access_token`
authenticator, without writing any JOSE code.

**Pre-1.0, so nothing here is stable yet.** Configuration keys are public API
and changes to them will be recorded with a deprecation path, but the surface is
still small enough that it should be expected to move. Asymmetric keys,
rotation and JWKS are the next phase, and only HMAC keys exist today.

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

[Unreleased]: https://github.com/medzuch/jwt-bundle/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.2.0
[0.1.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.1.0
