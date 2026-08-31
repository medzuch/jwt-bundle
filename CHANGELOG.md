# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Configuration keys under `medzuch_jwt:` are public API: a rename or removal is
a breaking change and is recorded here with its deprecation path, the same way
a class or method signature would be.

## [Unreleased]

### Added

- **An issuer can seal what it mints** (I8), under a `jwe` block on
  `issuers.<name>`: the token is signed first and the whole signed token
  encrypted after (RFC 7519 §11.2 asks for that order, and the type of what goes
  in is the only order this can express). It closes the pair with C12 — an application that is
  both ends now writes both blocks and never leaves the bundle.

  **One key and one algorithm of each kind**, where the reading side takes two
  allowlists and a list of keys. A receiver has to accept everything its senders
  might still be using; a sender picks. Rotating a sealing key is that asymmetry
  in practice: the receiving side's list grows first, and `key` here changes
  afterwards.

  **`replicated_claims`** copies claims into the outer header for an
  intermediary that holds no key — `iss`, so a gateway can route (RFC 7519
  §5.3). The value is read back out of the token that was just signed rather
  than assembled a second time, so the copy is the claim exactly, shape
  included; a receiver compares the two and must reject a token where they
  disagree, and this bundle's consumer does. A claim the token does not carry is
  not written, and a name that is a registered JOSE header parameter is refused
  at build. The default replicates nothing: every replicated claim is a claim
  you decided not to encrypt.

  Nothing above the envelope moved. The claims, the `expiresIn` reported back
  and the `jti` an application records to revoke on all belong to the token
  inside, and the issuance events fire on claims rather than on ciphertext. The
  container refuses an issuer whose key is not made of what its algorithm needs
  — `A256KW` with an `A192KW` key, or `dir` with a content key for a different
  `enc` — which is otherwise a 500 on a token endpoint rather than a failed
  deploy.

- **A consumer can read encrypted tokens** (C12), under a new `jwe` block and a
  new top-level `jwe_keys` section. What arrives is then a JWE wrapping the
  signed JWT (RFC 7519 §5.2 nested JWT); what is checked afterwards is
  unchanged, because the decrypting step is a decorator in front of the very
  verifier that would have judged an unencrypted token. An expired token in a
  perfect envelope is still refused as `expired`.

  **A bare signed token is refused once the block is there**, and there is no
  option to accept either. An attacker who could strip the outer layer and be
  believed would have taken the confidentiality of the claims for the cost of
  deleting two segments; moving an existing consumer onto encryption is done by
  the senders first.

  `jwe_keys` is a registry of its own rather than a sixth source under `keys`:
  RFC 7517 §4.2 asks that one key serve one purpose, and a signing algorithm and
  a key-management one come from different registries. Every scheme accepted
  this release takes a shared secret — `dir` and the six AES key-wrapping
  algorithms — so `secret` is the only source. ECDH-ES waits on a registry of
  asymmetric encryption keys; RSA key encryption is not coming, since the
  library implements none.

  A `dir` key is refused without a `kid`: the recipient falls back to the
  header's `alg`, which for direct encryption is the string `dir`, and no key is
  bound to that. The length of a secret is exact and cannot be known while the
  container is built, so `jwt:config:check` builds every JWE key — that row is
  where a 16-byte `A256KW` secret stops being a 500 on the first encrypted
  request.

  **`RejectionReason` gains `decryption_failed`**, kept apart from
  `signature_invalid` because the two fail in different halves of the pipeline
  and are fixed by different people. The profiler panel learned the same
  distinction: an encrypted token is described by its outer header — a new `enc`
  member on the collector's rows — instead of being shown under "this is not a
  JWT", which is what a token this bundle had just accepted used to get. `log_levels` gains `decrypted` and
  `decryption_failed`, the two categories the library always emitted and this
  bundle had nothing to emit them from. `TestTokenFactory::encryptedWith()`
  seals what the factory mints, refusals included, and `jwt:token:inspect`
  prints an encrypted token's outer header and still asks the consumer for a
  verdict instead of calling it something it cannot read.

  Minting them is I8, in this release as well.

- **This application can publish its own RFC 8414 metadata** (K8), under a new
  `metadata` section and `medzuch_jwt.metadata_controller`. It closes the pair
  with K7: what a remote key set's `discovery` reads from somebody else, this
  publishes about you, and the functional suite feeds one to the other rather
  than testing each against a fixture of its own.

  Named `metadata` rather than `discovery` because `discovery` already means the
  opposite in this tree.

  **Two members are filled in — `issuer` and `jwks_uri` — and the rest comes
  from `extra` verbatim.** Those two are the only ones a JWT bundle knows;
  everything else a metadata document carries describes an authorization server,
  which §8 of the plan keeps permanently out of this package. Naming either of
  them under `extra` is refused, since two spellings of one member could
  disagree and JSON may only answer once.

  **A document that would not survive being read back is refused before it is
  served.** RFC 8414 §2 requires `response_types_supported` and this bundle
  cannot supply it, so a missing one — or one that is not a non-empty list of
  names — fails at container build rather than being served with a 200. Both
  identifiers are HTTPS-only and the issuer may carry no query or fragment
  component, checked when the container is built for a literal value and again
  when the service is built, which is the only moment a `%env(APP_URL)%` has
  one. `jwt:config:check` builds the document, so a plaintext identifier is a
  red line in a deploy gate rather than a 200.

  As with the JWK Set, the bundle registers no route (DEC-6) — which is also
  what lets one controller answer at either well-known path, RFC 8414's or OIDC
  Discovery's.


- **Security Event Tokens, both halves** (C8 and I7, RFC 8417). A new
  `security_events` section configures the streams this application transmits
  and the transmitters it accepts deliveries from — RISC and CAEP events, and
  anything else built on SETs.

  Neither side is wired into a firewall, because a SET is not a credential: it
  says something happened to a subject who is not the caller, arrives in the
  body of a POST to a delivery endpoint, and grants nothing. Both are services
  your code calls, injectable by the name they were configured under, the same
  shape `IdTokenVerifier` already had.

  `SecurityEventIssuer::issue()` hands back the library's builder rather than
  taking an argument list, since what varies between two SETs from one stream is
  the events themselves. The stream supplies `iss`, `iat`, a random `jti`, the
  `secevent+jwt` type and the configured `audience`.

  **There is no TTL on either side.** RFC 8417 §4.1.4 makes `exp` meaningless
  for an event, so a replayed delivery verifies exactly like the first one and
  deduplicating on `jti` is the receiver's job. The README says so, and says why
  this bundle's denylist is not the seam for it: `revoke()` takes the moment an
  entry may be forgotten, which for a SET is nothing at all.

  Delivery — RFC 8935 push, RFC 8936 poll, and retries — stays the
  application's. This bundle mints and verifies.

  `secevent+jwt` joins `at+jwt` and `JWT` as a `token_type` a firewall consumer
  is refused: a consumer written that way would verify SETs without the
  `events` rule, which is the one shape this section exists to keep out of a
  firewall.


- **Endpoints that answer with or without a token are documented and pinned**
  (C15). A public path that shows more to a signed-in caller needs no
  authenticator and no configuration in this bundle: Symfony's `access_token`
  authenticator declines a request carrying no token rather than failing it, so
  an access rule exempting the path is the whole feature. The README and the
  cookbook say how, and a functional test holds the four behaviours that make it
  a promise rather than an accident — anonymous is served, identified is served
  as themselves, the guarded path next door still refuses, and a token that is
  present but garbled or expired is still a 401 with its `WWW-Authenticate`
  challenge rather than a silent downgrade to the anonymous view.

  No code changed. `docs/plan.md` §9 records the correction: DEC-1 had listed
  C15 as a reason a future authenticator might be needed, and it was wrong about
  what C15 requires.

- **A remote key set can be addressed by issuer identifier instead of by
  endpoint** (K7, the first of Phase 5). `remote_jwks.<name>.discovery` takes
  the issuer's identifier and reads `jwks_uri` from its
  `/.well-known/openid-configuration`, so the endpoint can move without a
  deploy. `uri` and `discovery` are alternatives: a set naming both, or
  neither, is refused when the container is built, as is either of them over
  plaintext — including a plaintext value that arrives from `%env(...)%`, which
  the container cannot read and the resolver refuses when it is first built.

  The metadata document has to state the issuer it was fetched for (OIDC
  Discovery §4.3) or it is refused — without that check, whoever answers the
  well-known path chooses which keys the application trusts. One trailing slash
  is tolerated and nothing else is. A `jwks_uri` that comes back over plaintext
  is refused when it arrives, since that URL is the issuer's to choose and no
  configuration can settle it in advance.

  Everything else is unchanged: the same client, cache, `cache_ttl`,
  `min_refresh` and `max_body_bytes`, and a discovery failure is the same
  `JwksResolutionException` a `jwks_uri` failure is, so locally configured keys
  still cover an outage.

### Changed

- **CI now tests the edges of the window the package promises**, which the
  legs above did not: `^8.0` was tested as `8.0.*`, and Symfony 8.1 had been
  released since May 2026 without any leg resolving it. The Symfony 8 leg is
  now `8.*`, so a minor reaches CI before it reaches an application, and a
  second 6.4 leg resolves with `--prefer-lowest --prefer-stable` — the floor as
  an application installs it, rather than whatever 6.4 patch was newest on the
  day. `composer.json` is unchanged: the supported window is the same
  `^6.4 || ^7.4 || ^8.0` DEC-2 set.

## [1.0.0] — 2026-08-25

Phase 4 of the roadmap in [`docs/plan.md`](docs/plan.md), and the end of the road to
1.0: DX and hardening. The plan's own test for this release is
"1.0 = the T1+T2 set, documented, with a BC policy", and all three criteria are
met — the last two capability rows (C7's custom token types and C10's freshness
ceiling) landed in this cycle, [`docs/cookbook.md`](docs/cookbook.md) and
[`UPGRADE.md`](UPGRADE.md) say how to use it and how to move between versions, and
[`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md) says what will not break.

**What 1.0 changes for you.** The configuration surface, eleven service ids, five
commands, the authorization names and nineteen classes are now covered by a
policy rather than by good intentions: a rename or a removal is a major release
with a deprecation path, and the suite holds the package to it — one test parses
the class table out of the Markdown and compares it with `src/` both ways, another
boots a container with one of everything and resolves every promised id to the
type its row names. What is deliberately *not* promised is written down too, so
the four service ids nobody should reach for say so by name.

**Upgrading from 0.3.0** takes no configuration change: everything added since is
inert until configured. One promised signature moved — `IssuedToken` gained a
third constructor argument, `$jti` — which costs a test double or a fixture that
builds one by hand, and nothing else. (`AccessTokenHandler`'s constructor moved
too, but it is `@internal` and the container builds it.)
[`UPGRADE.md`](UPGRADE.md) has the details.

### Added

- **Log levels are configurable (O1).** `log_levels` sets the PSR-3 level the library emits each
  kind of diagnostic at: `accepted`, `verification_failed`, `claim_rejected`, `key_resolution`
  and `key_resolution_failed`. Until now the bundle passed a logger and no `LogLevels`, so every
  application got the library's defaults and had no way to move them — which matters most for
  `accepted`, a line per request on a busy API, and for `claim_rejected`, the one an operator
  might want to alert on.

  Each category is optional and keeps the library's default when left out. They are passed as
  named arguments, so setting one does not restate the others at whatever this bundle believed
  their defaults were — including the two JWE categories there is deliberately no option for,
  since nothing here issues or consumes an encrypted token yet.

  A level that is not one of the eight PSR-3 strings is refused at container build, and so are
  levels configured with no `logger` to emit at them.

- **A token type of your own (C7).** `consumers.<name>.token_type` names the `typ` a consumer
  expects, and `required_claims` what a token of that type must carry. Everything else about the
  consumer is unchanged — keys, algorithms, issuer, audience, `audience_policy`, `leeway`,
  `max_token_age`, the denylist, user resolution, the scope voter, the RFC 6750 answers, the
  events and the profiler panel. What is replaced is the posture: the token is verified as a
  plain JWT bearing that type, with your list in place of the access-token profile's own.

  **Built on the library's lower-level API, which is where it belongs.** `04-api-surface.md`
  calls `ValidatorBuilder` "for multi-tenant or custom flows" and freezes it as public, its three
  profiles are the standardised postures, and its consumer constructors are `@internal`. So a
  custom posture is a `Validator`, not a fourth profile — a `typ` only one application knows has
  no posture to standardise, and reaching for the internal constructor to pretend otherwise would
  break the upstream rule this package's own policy promises to keep.

  Internally that is one small seam: `TokenVerifierInterface`, with the handler on one side and
  either the library's profile consumer or a bare validator on the other.

  Left out, `required_claims` is `["exp"]`, because the library checks `exp`, `nbf` and `iat`
  where a token carries them and nowhere else — a posture requiring none of them would take a
  bearer credential that never stops being valid. A list of your own replaces that, so one
  omitting `exp` is refused at container build unless `max_token_age` bounds the token instead,
  and one omitting `jti` is refused beside a denylist, which is what a denylist looks a token up
  by. The profiles all require `jti`, so that combination could not arise before this row.

  Three spellings of `token_type` are refused for naming something other than what they look
  like: `at+jwt` or `JWT`, which the library has profiles for — naming one here checks *fewer*
  rules than leaving the key out — the `application/` prefix RFC 7515 §4.1.9 keeps off the wire,
  and a value padded with whitespace. A `required_claims` entry that is not a string is refused
  too, rather than reaching `ClaimsSet::has()` as a `TypeError` on the first request.

  One thing is thinner than on the RFC 9068 path: a token too malformed to parse at all is not
  logged, because the library does that from inside its profile consumers. The refusal still
  reaches `JwtRejectedEvent` and the panel as `malformed`.

- **A ceiling on how old a token may be (C10).** `consumers.<name>.max_token_age` refuses a
  token whose `iat` is further back than that many seconds, however long its `exp` says it
  lives. `exp` is the issuer's decision about a lifetime; this is the application's about what
  it will accept, and the two are not the same question — an issuer you do not control minting
  day-long tokens is a token that keeps working for a day after it leaks.

  The refusal is its own `RejectionReason`, **`too_old`**, rather than `expired`. They are
  different facts about different clocks, and an operator watching them together would read a
  policy of theirs as an incident. `leeway` widens the window exactly as it widens `exp`, `nbf`
  and `iat`, because the age is computed across two clocks and inherits the skew.

  Off unless configured, so nothing is asked of a token that nobody set a ceiling for. A token
  carrying no `iat` is refused rather than exempted — unreachable through the access-token path,
  which requires it, and the alternative would exempt exactly the tokens whose age cannot be
  checked.

- **A configuration naming a service nobody has is refused at container build
  ([#3](https://github.com/medzuch/jwt-bundle/issues/3), D8).** `clock`, `logger`, a remote
  set's `http_client`, `request_factory`, `cache` or `cache_pool`, and a consumer's
  `denylist.service`, `denylist.cache`, `denylist.cache_pool` or `user.factory` are all service
  ids the application supplies, and all of them are now checked once every extension has run —
  which is the earliest the answer exists, since the service may belong to a bundle that has
  not been read yet.

  Symfony already refuses a *referenced* service that is missing, so most of what this adds is
  the message. `The service "medzuch_jwt.consumer.api" has a dependency on a non-existent
  service "app.jwt_logger"` names a service the application never wrote and never mentions
  `medzuch_jwt.logger`, which it did. The refusal now names the configuration key, lists every
  mistake at once rather than the first, and says when the id is a default nobody wrote:
  `psr18.http_client` without `framework.http_client` enabled, or `cache.app` without a cache.

  The part Symfony could not catch is an id nothing happens to reference. A `logger` with no
  consumer, issuer, ID token or remote set configured is referenced by nothing, so a typo in it
  compiled clean and the application ran without the logging it asked for; `clock` is the same
  wherever `symfony/console` is absent, which is a supported way to deploy this bundle. That is
  the shape the issue described, and the reason the check is a pass rather than one more
  refusal in `loadExtension()`.

  The pass runs at `TYPE_BEFORE_REMOVING`, which is the last point ahead of Symfony's own
  check and the first at which "does this service exist" has a final answer: a service can be
  registered by another *pass* rather than by an extension, and `monolog.logger.<channel>` — the
  id the `logger` option gives as its example — is exactly that. An `%env()%` in a service id is
  refused like any other, because a service id has to exist while the container is built and a
  placeholder in one never resolves to anything.

- **A backward-compatibility policy.** [`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md)
  says what 1.0 freezes and what it does not, across five surfaces: the `medzuch_jwt`
  configuration tree; eleven service ids, each with the type it answers; five console commands
  with their exit statuses and the three options a script may rely on; the `SCOPE_` prefix,
  `is_granted_scope()` and the claim-provider tag, which are names an application writes into its
  own configuration and break like any id; and nineteen classes and interfaces, each with what
  you may do with it — since an interface you implement is a stricter promise than an event you
  receive.

  Two rules the reader would otherwise have to guess: `RejectionReason` may gain cases and no
  case changes its backed value, and the types `medzuch/jwt-php` owns — a `ClaimsSet`, a
  `PrivateKey`, the exception hierarchy — are promised as far as that library promises them,
  with a move to a new major of it being a major release here.

  Everything else in `src/` is now marked `@internal`: the handlers, the extractor, the voter,
  the identity resolvers, the key loader, the controller, the compiler pass and the commands'
  classes. Thirteen classes gained the marker, so the reachable surface is the service id or the
  command name rather than the class behind it — which is what lets the class behind it move.

  **Three of the five surfaces are read back out of the document and checked against the code.**
  `tests/Unit/BackwardCompatibilityTest.php` — the first case in a new `unit` suite, which needs
  no kernel — compares the class table to `src/` in both directions, holds every class to
  `final`, and fails if the support window here and the constraints in `composer.json` disagree.
  `tests/Functional/PublicSurfaceTest.php` boots a container configured with one of everything
  and resolves every promised id to the type its row names, then asserts every promised command
  is registered where the policy says it is, with `--raw`, `--compact` and `--skip-remote` still
  on it.

  The configuration tree is the surface that is *not* held that way, and the document says so
  rather than claiming otherwise: what covers it today is `DocumentationExamplesTest` compiling
  every documented example, which is real and narrower than the promise.

  What the policy deliberately does not cover is named too: what a command prints, what a log
  line or an exception message says, the profiler template, the ordering of two claim providers
  at equal priority, and behaviour a security fix has to change.

- **A cookbook and upgrade notes (D7).** [`docs/cookbook.md`](docs/cookbook.md) carries the
  recipes that need several features at once and so fit no single README section: machine
  tokens between your own services, two issuers on one API, a deployment serving several
  tenants, a browser SPA on a `__Host-` cookie, and gating a deploy on `jwt:config:check`.
  Each says what the bundle does not do for it — there is no client-credentials grant, no
  falling through consumers in turn, and a tenant is a claim rather than its own issuer until
  C11's issuer dispatch (§3.1) exists.

  [`UPGRADE.md`](UPGRADE.md) says what each release asks of an application already running the
  previous one, which a changelog does not: the changelog says what changed. Nothing has been
  removed or renamed in any release so far, so what it carries is behaviour an upgrade could
  notice — the scope voter now voting beside one of your own under a non-`affirmative`
  strategy, `IssuedToken`'s third constructor argument, the RFC 6750 answers being opt-in, and
  the profiler decorating the handler the firewall calls wherever `framework.profiler` is on.

  The README keeps its job as the reference and gains the two pointers its own introduction
  implied but never gave: the OIDC relying party has a section of its own, and
  service-to-service is a recipe.

  **The suite holds all of it to the bundle.** `ReadmeExamplesTest` is now
  `DocumentationExamplesTest`: every `medzuch_jwt` example in the README *and* the cookbook is
  compiled into a real container, every `medzuch_jwt.*` service id any of the three documents
  names has to be one an example builds, and every relative link resolves — file and heading
  both. `UPGRADE.md` writes its before-and-after as `diff` rather than `yaml` precisely because
  the half being migrated away from is configuration that no longer compiles.

- **A profiler panel (O2).** Every token a consumer was shown during the request, with the
  verdict, the `RejectionReason` behind a refusal, the algorithm and key id the token named, the
  identity it would have authenticated as, and the milliseconds spent verifying. The reason is
  the point: the response says `invalid_token` and nothing else, and the panel is where it is
  safe to say which of a dozen things that covers.

  Wired by a compiler pass — the bundle's first — which decorates the handler the firewall
  actually calls and only where `framework.profiler` is enabled. What SecurityBundle calls is a
  `ChildDefinition` of the configured handler under a name keyed by the firewall, so decorating
  the bundle's own service would collect nothing.

  The token is never collected: profiler data outlives the request on disk and in a URL. The
  panel shows the claims as the token has them — unverified, which is all a refused token has.

- **`jwt:config:check` (O5).** Builds every configured key, consumer, issuer and ID-token
  verifier, then reaches every remote JWK Set, and reports what failed. The container refuses
  the mistakes it can see; this is for the ones it cannot — a key file that was not deployed, an
  env variable that arrived empty, a secret shorter than its algorithm allows, an issuer
  unreachable from this host — all of which are factory arguments today, and so surface on
  somebody's first request. Exit status gates a deploy step: `0` when everything answered, `1`
  when anything did not, `2` when nothing was configured to check — an application whose package
  file never deployed should not pass a gate by having nothing to fail. `--skip-remote` for a
  gate with no network, which reports what it skipped rather than passing quietly. The published
  JWK Set is read for private material, the one thing that document must never carry.

  `ok` means built: a consumer's denylist is constructed but not asked anything, while an
  issuer's claim providers are constructed, which is the point.

- **Test helpers for the applications using this bundle (D5).** `Medzuch\JwtBundle\Test\TestTokenFactory`
  mints what an issuer will not: a token that expired an hour ago, one not valid for another
  hour, one addressed elsewhere, one from an issuer nobody trusts. It reads no configuration on
  purpose — a test minting from the same container it verifies against cannot catch an
  `audience` that is wrong in both halves. A token signed by a stranger is a second factory
  rather than a method, so every algorithm gets the same answer.

  `Medzuch\JwtBundle\Test\AssertsBearerChallenges` says what a refusal carried without pinning
  the whole header: `assertBearerChallenge()` (and no `error`, per RFC 6750 §3),
  `assertInvalidToken()`, `assertInsufficientScope()` and `assertNoBearerChallenge()`. Parameters
  are read by name, so a test does not fail over the spacing Symfony's header and this bundle's
  differ in.

  Time travel needs no helper: `medzuch_jwt.clock` already takes any PSR-20 service, so a frozen
  clock in `config/packages/test/` reaches every consumer, issuer and denylist at once. The
  README shows the four lines.

- **`jwt:jwks:dump` (D4).** Prints the JWK Set the endpoint serves, from the same `JwkSet`
  service, so a document written to a file cannot drift from one served over HTTP. Indented by
  default; `--compact` is byte for byte what `medzuch_jwt.jwks_controller` returns, for
  `> public/.well-known/jwks.json`. Registered only where `medzuch_jwt.jwks` names keys.

- **`jwt:token:create` and `jwt:token:inspect` (D1, D2).** Mint a token from the command line
  and ask what a consumer makes of one. Neither is a second implementation: `create` calls
  `AccessTokenIssuer::issue()`, so the configured key signs it and the application's claim
  providers and issuing listeners run; `inspect` verifies through the consumer's own handler,
  so its answer is the firewall's. `--raw` prints the token alone for a shell to capture, and
  `jwt:token:inspect -` reads one from a pipe.

  Inspecting decodes with or without configuration — header, claims, and the instants among
  them rendered as instants in the application clock's own zone, not the machine's — and names
  the reason a refusal keeps off the wire (`… refuses this token: expired`). Values out of the
  token are escaped before display, since a claim carrying console markup would otherwise print
  as something the token does not say. Exit status is scriptable: `0` accepted or decoded with
  no consumer configured, `1` refused, `2` nothing to inspect — including several consumers
  configured and none named, which is a usage error rather than a pass.

  `--issuer` and `--consumer` can be left out where one is configured, whatever it is called;
  `--issuer` falls back to `default` among several. Every bad input is refused before anything
  is signed, the registered claims given to `--claim` included.

  `jwt:token:create` is registered only where an issuer is configured; `jwt:token:inspect`
  always, since decoding needs nothing. Both reach their subjects through a service locator
  built from the configured names, so neither can be asked for a service nobody named.

- **Why a token was refused (O3).** `JwtRejectedEvent` carries the consumer, the exception,
  and a `RejectionReason` — `expired`, `signature_invalid`, `unknown_key`,
  `algorithm_refused`, `wrong_issuer`, `wrong_audience`, `revoked`, `malformed`,
  `claims_refused`, `keys_unavailable`, `identity_refused`, `not_yet_valid`, `other`. Symfony's
  own `LoginFailureEvent` reaches a listener with the same generic message for every refusal,
  which is right on the wire and useless on a dashboard. `JwtVerifiedEvent` is the other side:
  the consumer, the claims, and the identity the request will authenticate as.

  The reasons are coarser than the library's exception hierarchy on purpose — a case per
  exception class would only move the coupling, and every dashboard would have to learn a new
  name whenever the library grows a leaf. The distinctions kept are the ones an operator acts
  on differently, `keys_unavailable` above all: an issuer that cannot be reached is an outage,
  not a verdict on the token.

  Refusals now throw `RejectedTokenException`, a `BadCredentialsException` that carries its
  reason. Nothing changes on the wire: `getMessageKey()` is inherited, so a rejected token
  still gets Symfony's generic "Invalid credentials." and none of the detail behind it.

  Neither event carries the token. Both are dispatched only where an application has an event
  dispatcher, which outside a framework it may not.

- **Claims an application contributes (I3, I4).** `TokenClaimProviderInterface` services add
  claims to every token an issuer mints — a tenant, an entitlement list, anything that has to
  be looked up rather than configured. Implementing the interface is the whole registration;
  autoconfiguration tags it. Providers are handed a `TokenIssuance` describing what is being
  minted (issuer name, subject, scopes, audience, TTL and the `jti` the token will carry), run
  in tag priority order, and the one that runs later wins.

  `JwtIssuingEvent` is the same hook for code that cannot be a provider — another bundle's
  listener, a subscriber that also listens for something else. It runs last, after the
  providers and after the caller's own `issue()` claims, because adjusting a claim set means
  seeing all of it. `JwtIssuedEvent` follows the signature, for audit and metrics: it carries
  the issuance and the claims, and deliberately **not** the token, so a listener logging what
  it is handed cannot log a working credential.

  Neither hook may set `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `client_id` or `scope`;
  doing so throws, naming the provider class or the event. The registered ones the library
  already refuses, but from inside a builder, where the message cannot say whose contribution
  it was; `client_id` and `scope` nothing refused at all, and a provider runs for tokens it was
  never asked about, so one rewriting `scope` would widen every token in the application.
  Configuration and the `issue()` arguments may still set those two, as before.

- **RFC 6750 refusals (O4).** `medzuch_jwt.entry_point.<name>` and
  `medzuch_jwt.access_denied.<name>` supply the two answers Symfony has none of. A request
  carrying no token is challenged with `WWW-Authenticate: Bearer realm="…"` and **no
  `error`**, which RFC 6750 §3 asks for: naming `invalid_token` to a caller who sent no
  token describes a failure that did not happen. A request denied for want of a scope gets
  `403` with `error="insufficient_scope"` and the scope that would have sufficed — not a
  leak, since the caller is authenticated and could ask their authorization server for it,
  while withholding it leaves them retrying something that can never succeed.

  A token Symfony rejects keeps its existing answer, `error="invalid_token"` and nothing
  about why: expired, wrong audience or revoked all read the same on the wire, and the
  reason stays in the log. A denial over a role, an expression or a voter of your own is
  left alone — including a denial through an `allow_if` expression, which carries the
  expression rather than the attribute it asked about, so a rule wanting the header names
  `SCOPE_*` directly.

  `consumers.<name>.realm` names the protection space, defaulting to the consumer's name,
  and is refused at container build if it carries a quote or a backslash — both would close
  the quoted-string they are interpolated into. Symfony has its own `access_token.realm` for
  the header it sends itself; the two are one string written twice, because a bundle setting
  Symfony's would be deciding which firewall a consumer belongs to (DEC-1).
- **A scope voter (C13).** `SCOPE_*` attributes — `#[IsGranted('SCOPE_reports.read')]`,
  `access_control` rules, `is_granted()` — are answered from the token's `scope` claim,
  space-delimited per RFC 6749 §3.3. Registered unconditionally and with nothing to
  configure: it answers `SCOPE_*` and only that, so an application whose tokens carry no
  scopes never asks.

  Scopes stay their own namespace rather than being mapped into roles, because they are not
  the same statement: a role says what someone is and outlives any one token, a scope says
  what the client holding this token was allowed to ask for on their behalf. It needs a user
  implementing `ProvidesScopes` — `user.mode: claims` builds one, a `custom` factory can, and
  so can a user loaded from your own store — and what the voter looks at is the user, not the
  mode, so a `provider`-mode check is refused for as long as your user class says nothing
  about scopes.

  A `scope` claim sent as a JSON list of strings is read as well as the space-delimited
  string the RFCs describe: issuers send it, the intent is unambiguous, and refusing it would
  deny every scope check for a token that authenticates perfectly. The claim name itself is
  not configurable — an issuer keeping scopes elsewhere, such as Entra ID's `scp`, is read by
  a `custom` factory, which gets the whole claim set.

  Denial matters under a non-default access decision strategy: with `affirmative` this voter
  cannot override another's grant, while under `unanimous` or `consensus` it votes like any
  other.

  With `symfony/expression-language` installed, `is_granted_scope('reports.read')` says the
  same thing in an expression, with the prefix kept out of the string.
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
  to add — as is the extractor order, since Symfony's chain stops at the first extractor
  that finds anything: with the header listed first, a browser sending any `Authorization`
  header at all gets a 401 while its cookie sits unread. `same_site_only: true` ignores the cookie when the browser reports a cross-site
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

### Changed

- **`AccessTokenHandler`'s constructor takes the freshness policy**, so `$clock` is now its
  fourth argument and `$maxTokenAge`/`$leewaySeconds` sit ahead of `$denylist` and `$events`.
  The class is `@internal` and
  [`BACKWARD-COMPATIBILITY.md`](BACKWARD-COMPATIBILITY.md) promises
  `medzuch_jwt.handler.<consumer>` as an `AccessTokenHandlerInterface` rather than as this class,
  so nothing an application was told to write is affected — but positional construction or a
  decoration of the concrete class is, and a release note that only says "Added" would not have
  said so.

### Fixed

- **A key whose armour was mangled is no longer printed in the error (K9).** A `pem_*` or `jwk_*`
  value is read as a document or as a path depending on how it starts, and a value that is
  neither — an inline key that lost its `-----BEGIN` line somewhere between the secret store and
  the configuration — was quoted back in full by the exception naming both readings. That message
  reaches the log, the error page, `jwt:config:check` and the profiler at once, which is exactly
  where key material must never be.

  What gets quoted is now decided by what a path looks like rather than by what a key looks like:
  one line, no longer than `PATH_MAX`, and made of components no longer than 40 characters. A
  negative rule would have to be told about every key shape in advance, and the first one it was
  never told about is real — a P-256 PKCS#8 body folded onto one line is 184 bytes with no
  armour, no newline and no `"d"`. The cost is a bare filename carrying no separator and no
  suffix, which is described by its size like anything else; the message still names the
  algorithm, and the container names the key.

- **A listener can no longer delete what it cannot write ([#31](https://github.com/medzuch/jwt-bundle/issues/31)).**
  `JwtIssuingEvent::setClaim()` refused the claims the issuer decides itself; `removeClaim()`
  refused nothing, so a listener could drop a `scope` that `issuers.*.claims` deliberately put
  there and mint a token granting less than the configuration says, with nothing saying so. Both
  halves of writing are refused now.
- **`WWW-Authenticate` carries only what it can carry ([#32](https://github.com/medzuch/jwt-bundle/issues/32)).**
  Quoting covered `"` and `\`; a control character has no place in a quoted-string either (RFC
  9110 §5.6.4), and a newline costs more than a wrong value — PHP refuses to emit a header
  carrying one, so the `401` would go out with no challenge at all. `consumers.*.realm` refuses
  a quote, a backslash and a control character at container build, which also means it must be
  a literal rather than an env reference: Symfony declines to validate a placeholder.

  A `SCOPE_*` attribute the bundle never sees until a request is denied is now held to RFC 6749
  §3.3 instead: only a real `scope-token` reaches the `scope` parameter, and a rule whose
  attributes are none — one carrying a space, say, which would arrive at the client as two
  scopes it never asked about — is answered with a plain `403` and no challenge. RFC 6750 §3.1
  makes the parameter optional; saying nothing is allowed, saying something untrue is not.

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
- **CI across the supported Symfony lines** — 6.4, 7.4 and 8.0 against PHP
  8.3 and 8.4, with `symfony/flex` pinning each leg to its Symfony line. Every
  action is pinned to a commit SHA, which the repository enforces. A weekly
  scheduled run re-resolves dependencies so upstream drift reports itself
  instead of reddening an unrelated pull request.
- Repository policy: contribution and security guidelines, PR template,
  Dependabot configuration for GitHub Actions, and branch/tag protection
  rulesets (`main` requires a pull request and merge commits; `v*` tags cannot
  be moved or deleted).

[Unreleased]: https://github.com/medzuch/jwt-bundle/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v1.0.0
[0.3.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.3.0
[0.2.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.2.0
[0.1.0]: https://github.com/medzuch/jwt-bundle/releases/tag/v0.1.0
