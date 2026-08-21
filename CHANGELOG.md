# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Configuration keys under `medzuch_jwt:` are public API: a rename or removal is
a breaking change and is recorded here with its deprecation path, the same way
a class or method signature would be.

## [Unreleased]

### Added

- **A cookie token extractor (C5).** `token_extractors.<name>.cookie` registers
  `medzuch_jwt.token_extractor.<name>`, to be named in a firewall's
  `access_token.token_extractors` beside Symfony's own `.header`, `.query_string` and
  `.request_body`. The cookie is the one Symfony does not ship and the one a browser
  needs: a single-page application keeping its token in JavaScript keeps it where any
  injected script can read it.

  The trade is stated in the README rather than left to be discovered: a token in an
  `Authorization` header is immune to CSRF by construction, a cookie is attached by the
  browser to requests your application did not initiate, and moving the token buys
  protection from script access in exchange for cross-site request forgery. `SameSite`,
  the `__Host-` prefix and CSRF protection on state-changing routes are the application's
  to add. `same_site_only: true` ignores the cookie when the browser reports a cross-site
  request — defence in depth, off by default, and explicitly not a CSRF defence, since a
  request without `Sec-Fetch-Site` is not judged at all.
- **Token revocation (C9).** `consumers.<name>.denylist` gives a consumer somewhere to ask
  whether a token has been withdrawn since it was issued — a logout, a leak, an account
  suspended mid-session. Keyed on `jti`, which RFC 9068 §2.2 makes required, so every
  accepted token can be named. `cache_pool` (a PSR-6 pool, wrapped) or `cache` (a PSR-16
  service) builds the shipped `CacheTokenDenylist`; `service` takes an implementation of
  `TokenDenylistInterface` of your own, for a store that survives a cache flush.

  The denylist is registered as `medzuch_jwt.denylist.<name>`, public and injectable as
  `TokenDenylistInterface $<name>`, because revocation is half a feature if nothing can
  revoke. An entry outlives only the token it refuses: after `exp` the token is refused on
  its own terms, so `revoke()` takes the moment to hold until rather than a duration.

  Configured, it costs a lookup per request. Unconfigured, nothing is asked and no service
  exists — where DEC-3 called for a `NullDenylist`, there is simply nothing, since a
  service that always answers "not revoked" would tell `debug:container` that revocation is
  configured when it is not.
- **`IssuedToken::$jti`.** A token you minted carries the id it can later be revoked by, for
  the same reason it already carried its lifetime: reading it back means parsing what was
  just built. Its constructor takes a third argument — a signature change, though the class
  is a return value nothing outside the bundle constructs.

- **User modes `claims` and `custom` (C3), and claim-to-role mapping (C4).**
  `consumers.<name>.user.mode` decides where the user comes from. `provider` is the
  default and unchanged: the identifier goes to the firewall's user provider. `claims`
  builds a `JwtUser` from the token and consults no store — the mode for a resource
  server verifying a third party's tokens, where there is nothing to look up and a local
  row keyed on `sub` would be a copy that goes stale. The user keeps the whole claim set,
  so a controller reads `$this->getUser()->claims()` instead of parsing the token again.
  `custom` hands the claims to a service implementing `JwtUserFactoryInterface`.

  Roles come from a claim under `user.roles`: a list (`["staff","billing"]`) or a
  delimited string (`scope`, space-delimited per RFC 6749 §3.3), with a configurable
  prefix and a baseline every token gets. Anything else in the claim contributes no roles
  — a value under some key is not a grant.

  An option naming another mode's answer is refused at container build rather than ignored:
  a `factory` where nothing calls one, a `roles.claim` or `roles.defaults` where the
  provider or the factory decides roles, and an empty roles separator, which `explode` has
  no reading for. `roles.separator` and `roles.prefix` carry defaults, so a value set
  outside `claims` mode cannot be told from one never written and is simply unread.

  In `custom` mode the factory names the user it builds — `identity_claim` is not
  consulted — so an identity assembled from several claims is fine and the badge cannot
  disagree with the user it loads.

## [0.3.0] — 2026-08-20

Phase 3 of the roadmap in [`docs/plan.md`](docs/plan.md): federation. Keys can now
come from the issuer rather than from your configuration, an OIDC provider's ID
tokens can be verified where they arrive, and a consumer can insist that a token
was minted for it alone.

**Still pre-1.0.** Configuration keys are public API and changes to them are
recorded with a deprecation path, but the surface is young enough that it should
be expected to move. Nothing in 0.2.0 was removed or renamed, and no default
changed: `consumers.<name>.keys` merely stopped being mandatory, and the new
sections are inert until configured.

### Added

- **Remote JWK Sets (K5).** A consumer can verify against an issuer's published keys
  instead of keys configured here: `remote_jwks.<name>.uri` is fetched through a PSR-18
  client, cached through PSR-16, and referenced by `consumers.<name>.remote_jwks`. Keys
  the issuer rotates to are picked up without a deploy. The defaults name Symfony's own
  services — `psr18.http_client` and `cache.app`, the latter wrapped for the PSR-16
  interface the resolver takes — so an application with `framework.http_client` enabled
  configures a URI and nothing else. HTTPS only, and a plaintext URI written literally is
  refused at container build rather than when the first token arrives. Responses are
  bounded (256 KB by default), the document is cached (`cache_ttl`, 300s), and a token
  naming an unknown `kid` buys at most one refetch per `min_refresh` (60s), so tokens
  bearing kids nobody published cannot be amplified into a fetch storm against the issuer.
- **Local keys and a remote set together (K6).** Name both and the local keys are tried
  first: a key already configured is never a round trip, and an unreachable issuer cannot
  stop tokens signed with keys this application holds. A key the issuer has rotated to
  falls through to the fetched set. There is no failover mode to configure and nothing
  that behaves differently on the day the identity provider is down. The cost is the
  same property seen from the other side: a key configured locally is outside the
  issuer's rotation, so when they drop it — expired, or leaked — tokens signed with it
  keep verifying against your copy until the entry is deleted.

- **ID tokens for OIDC relying parties (C6).** `id_tokens.<name>` registers a provider
  and the client you are registered as, and `medzuch_jwt.id_token.<name>` — injectable as
  `IdTokenVerifier $<name>` — verifies a token the provider handed you: signature and
  algorithm, `iss`, `aud` against your `client_id`, `azp` when the token names more than
  one audience, `exp`/`iat`, the claims OIDC requires, and the `nonce` you pass. Keys come
  from the same sources a consumer uses, local or remote.

  **There is no firewall authenticator for it, deliberately.** An ID token says who
  authenticated to the client that asked for it; it is not a bearer credential for an API,
  and accepting one as such is the confusion RFC 9068 exists to end. The bundle gives a
  service to call where an ID token legitimately arrives — the OIDC callback — and nothing
  that can be wired into `access_token`.

  The `nonce` is passed per call rather than configured, because it belongs to one
  authentication request; a value fixed at deploy is not a nonce. `at_hash` is **not**
  checked: binding an ID token to an access token needs support the library does not have,
  and this bundle does not reimplement crypto its library is missing.

- **Audience policy (C14).** `consumers.<name>.audience_policy: exclusive` refuses a token
  that is addressed to anyone besides this consumer, which is what RFC 9068 §3 asks of an
  access token: a token minted for several services is valid at each of them, so it only
  has to leak from the least careful one to arrive here. The default, `any`, is unchanged
  and is what RFC 7519 §4.1.3 describes — a token naming us is for us, whoever else it
  names. Exclusivity is about audiences you did not configure, not about the token naming
  all of yours: an application answering to two names is addressed by either.

### Changed

- **`consumers.<name>.keys` is no longer required**, since a consumer may verify entirely
  against a remote set. A consumer with neither `keys` nor `remote_jwks` is refused, with
  a message naming both.
- **With a remote set configured, the "every allowed algorithm has a key" check is not
  made.** The issuer publishes their algorithms at runtime and may rotate to one this
  application has never seen, so the question has no build-time answer. Without a remote
  set the check is unchanged.

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

[Unreleased]: https://github.com/medzuch/jwt-bundle/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.3.0
[0.2.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.2.0
[0.1.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.1.0
