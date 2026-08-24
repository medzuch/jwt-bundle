# Backward compatibility

What this package promises not to break, and what it reserves the right to change.

**The promise starts at 1.0.** Until then the surface is young enough that a minor release may
move it, which is what every release note so far has said. What is written below is the shape
1.0 freezes; [`UPGRADE.md`](UPGRADE.md) is where a release says what it asks of you, and
[`CHANGELOG.md`](CHANGELOG.md) what it changed.

From 1.0 the package follows [semantic versioning](https://semver.org): the public surface below
changes only in a major release, and only after a minor release has deprecated what it changes.

## The public surface

Five kinds of thing, and they are not all promised in the same way.

### Configuration

Everything under the `medzuch_jwt` root key: the section names, the option names, their defaults
and what a value means. `config:dump-reference medzuch_jwt` prints the tree you have, generated
from the bundle rather than copied by hand.

A configuration that boots on 1.x keeps booting on every later 1.x, and keeps meaning the same
thing. New options may be added — with a default that changes nothing — and existing ones may be
deprecated, but neither costs an application a rewrite.

### Service ids

The ids the documentation tells you to name, all of them derived from a name you chose. The type
is the promise; the class behind it is not:

| Id | Answers | What names it |
|---|---|---|
| `medzuch_jwt.handler.<consumer>` | `Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface` | a firewall's `access_token.token_handler` |
| `medzuch_jwt.entry_point.<consumer>` | `Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface` | a firewall's `entry_point` |
| `medzuch_jwt.access_denied.<consumer>` | `Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface` | a firewall's `access_denied_handler` |
| `medzuch_jwt.denylist.<consumer>` | `Medzuch\JwtBundle\Revocation\TokenDenylistInterface` | your code, to revoke a token |
| `medzuch_jwt.issuer.<issuer>` | `Medzuch\JwtBundle\Issuer\AccessTokenIssuer` | your code, to mint one |
| `medzuch_jwt.login.<issuer>` | `Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface` | an authenticator's `success_handler` |
| `medzuch_jwt.id_token.<registration>` | `Medzuch\JwtBundle\Oidc\IdTokenVerifier` | your code, to verify an ID token |
| `medzuch_jwt.token_extractor.<extractor>` | `Symfony\Component\Security\Http\AccessToken\AccessTokenExtractorInterface` | a firewall's `access_token.token_extractors` |
| `medzuch_jwt.key.<key>.signing` | `Medzuch\Jwt\Key\PrivateKey` | your code, for a key you configured |
| `medzuch_jwt.key.<key>.verification` | `Medzuch\Jwt\Key\PublicKey` | your code, for a key you configured |
| `medzuch_jwt.jwks_controller` | `callable` | a route's `controller:` |

**`medzuch_jwt.jwks_controller` is the row where a type would say nothing.** Its class is
`@internal`, and a route depends on behaviour rather than on a class name: it is invokable,
takes nothing it is not given, and answers the JWK Set as JSON with an `ETag`. That is what is
promised.

**A key answers by role because only one role may exist**: an entry given a public half alone
has a `.verification` service and no `.signing` one, and a shared secret is both at once. The
bare `medzuch_jwt.key.<key>` is where the half you configured is built and keeps working, but it
is not in the table — which of the two it means depends on the entry.

**Two ids also answer by argument name**, which is part of the promise: `IdTokenVerifier $partner`
reaches `medzuch_jwt.id_token.partner`, and `TokenDenylistInterface $api` reaches
`medzuch_jwt.denylist.api`. Issuers do not: only an issuer named `default` is reachable by type,
and the rest are named explicitly.

Any other id — anything not in that table, and anything with `.profile`, `.key_set` or a similar
suffix naming a part rather than a whole — is wiring, and moves without notice.

**Three are deliberately absent although they look like they belong**: `medzuch_jwt.consumer.<consumer>`,
the verifier the handler wraps; `medzuch_jwt.remote_jwks.<set>`, the resolver behind it; and
`medzuch_jwt.clock`, which every dated decision reads. All three are stable and none is
documented as something to name, and promising an id nobody was told to use freezes the type
behind it for no reader. Each joins the table as soon as the documentation gives it a use —
verifying a token outside a firewall being the obvious one.

### Console commands

The names, their arguments and options, and their exit statuses:

| Command | Registered | Exit statuses |
|---|---|---|
| `jwt:key:generate` | always | `0` written, `1` refused |
| `jwt:config:check` | always | `0` everything built, `1` something failed, `2` nothing configured |
| `jwt:token:inspect` | always | `0` accepted, `1` refused, `2` not a JWT |
| `jwt:token:create` | where an issuer is configured | `0` minted, `1` refused |
| `jwt:jwks:dump` | where a JWK Set is published | `0` printed, `1` nothing to print |

**A command is promised where the thing it operates on is configured**, not as a fixture of every
container. A resource server that mints nothing has no `jwt:token:create`, and one that publishes
no JWK Set has no `jwt:jwks:dump` — a command whose every run could only say "nothing is
configured" has no business in `bin/console list`. All five need `symfony/console`, which is a
`suggest` rather than a `require`.

What they *print* is not covered. Tables, colours and wording are for a person reading a
terminal. Three options exist because a script needs something stable, and those three are:
`--raw` on `jwt:token:create`, `--compact` on `jwt:jwks:dump`, and `--skip-remote` on
`jwt:config:check`.

### Classes and interfaces

Only these, and each only in the way its row says:

| | Use it | Call it | Extend it | Implement it |
|---|---|---|---|---|
| `MedzuchJwtBundle` | register it in `bundles.php` | no | no | — |
| `Issuer\AccessTokenIssuer` | inject it | yes | no | — |
| `Issuer\IssuedToken` | receive it | yes | no | — |
| `Issuer\TokenIssuance` | receive it | yes | no | — |
| `Issuer\TokenClaimProviderInterface` | — | — | — | **yes** |
| `Event\JwtIssuingEvent` | receive it | yes | no | — |
| `Event\JwtIssuedEvent` | receive it | yes | no | — |
| `Event\JwtVerifiedEvent` | receive it | yes | no | — |
| `Event\JwtRejectedEvent` | receive it | yes | no | — |
| `Security\RejectionReason` | read it, match on it | yes | — | — |
| `Security\RejectedTokenException` | catch it, throw it | yes | no | — |
| `Security\User\JwtUser` | receive it | yes | no | — |
| `Security\User\JwtUserFactoryInterface` | — | — | — | **yes** |
| `Security\User\ProvidesScopes` | type-hint it | `scopes()` | — | **yes** |
| `Revocation\TokenDenylistInterface` | inject it | `revoke()`, `isRevoked()` | — | **yes** |
| `Oidc\IdTokenVerifier` | inject it | yes | no | — |
| `DataCollector\JwtDataCollector` | read it, in a panel of your own | its readers | no | — |
| `Test\TestTokenFactory` | use it in your tests | yes | no | — |
| `Test\AssertsBearerChallenges` | use it in your tests | yes | — | — |

Every class in this package is `final`, so "extend it: no" is enforced rather than asked, and the
suite keeps it that way. What the table adds is the distinction `final` cannot make:

- **An interface you implement** is the strictest promise here. Adding a method to
  `TokenClaimProviderInterface`, `JwtUserFactoryInterface`, `ProvidesScopes` or
  `TokenDenylistInterface` breaks every implementation, so it happens in a major release only.
  Two of them are called as well as implemented: `medzuch_jwt.denylist.<consumer>` is promised
  as somewhere to revoke a token, which is `revoke()` and `isRevoked()`, and a user's `scopes()`
  is what the voter reads and what your own code reads beside it. An id promised to resolve to a
  type nobody may call would not be a promise.
- **A class you receive** — an event, an `IssuedToken`, a `TokenIssuance` — may gain methods and
  readable properties in a minor release. Nothing you wrote against the old shape stops working;
  you simply have more to read. `JwtIssuingEvent` is the exception that is also written to:
  `setClaim()` and `removeClaim()` are how a listener contributes, so their signatures are as
  fixed as any interface method.
- **A service is obtained, not constructed.** `AccessTokenIssuer` and `IdTokenVerifier` have
  public constructors because PHP has no package-private, and what is promised is the id and the
  methods, not the constructor's arguments. `IssuedToken` and `TokenIssuance` are the other way
  round — you receive them from us, and a test fixture that builds one is building the same thing
  we do, so their constructors are promised.
- **`RejectionReason` may gain cases, and no case changes its value.** It is a vocabulary for a
  dashboard, and a new kind of refusal has to be nameable, so `match` on it without a `default`
  and a new case is a fatal error — a good reason to write the `default`, and the reason this is
  said here rather than discovered. What a dashboard actually stores is the backed value, and
  those do not move: `expired`, `not_yet_valid`, `too_old`, `signature_invalid`, `unknown_key`,
  `algorithm_refused`, `wrong_issuer`, `wrong_audience`, `revoked`, `malformed`,
  `claims_refused`, `keys_unavailable`, `identity_refused`, `other`.
- **`JwtDataCollector`'s mutators are not yours.** The tracing decorator writes to it; an
  application reads it. The read side is what the table covers, and a panel of your own reads
  rows keyed `consumer`, `verdict` (`accepted` or `refused`), `reason`, `detail`, `identity`,
  `alg`, `kid`, `duration` and `claims` — keys that may gain company and will not lose members.
- **`AssertsBearerChallenges` is a trait**, so its methods land in your test case. A new
  assertion is additive unless you already have a method by that name, which is the one way
  adding to it can break you — new names are chosen to be unlikely, not guaranteed.

**Everything else in `src/` is internal**, marked `@internal` and free to change in any release —
the handlers, the extractors, the voter, the resolvers, the key loader, the commands' classes,
the compiler pass, the controller. They are reachable by service id or by command name, and those
are covered above; the classes are not.

### Authorization names, and one tag

Three strings an application writes into its own configuration, and none of them a class:

| Name | Where you write it |
|---|---|
| the `SCOPE_` prefix | `#[IsGranted('SCOPE_reports.read')]`, `access_control` rules, `is_granted()` |
| `is_granted_scope()` | an expression, with `symfony/expression-language` installed |
| the `medzuch_jwt.token_claim_provider` tag | a claim provider that needs a priority rather than autoconfiguration |

They are as public as a service id and break the same way. A rule naming `SCOPE_reports.read`
depends on that prefix exactly as `security.yaml` depends on `medzuch_jwt.handler.api`, and the
expression function is compiled into the same file. The classes behind all three — `ScopeVoter`,
`ScopeExpressionProvider`, and the interface's autoconfiguration — are `@internal`; the names are
not.

New names may be added. These three do not move.

### The types `medzuch/jwt-php` owns

Some of what this package hands you belongs to the library underneath it: a `ClaimsSet` from
`JwtVerifiedEvent::$claims`, `JwtUser::claims()` and `IdTokenVerifier::verify()`; the
`PrivateKey` and `PublicKey` a key service answers; the algorithms and keys `TestTokenFactory`
takes; the `JwtException` hierarchy `RejectionReason::of()` reads.

**They are promised as far as `medzuch/jwt-php` promises them**, which since its 1.0.0 is
strictly: no incompatible change to its documented surface within 1.x. This package's `require`
names one major of it, and **moving that constraint to a new major is a major release here** —
the same rule as raising the PHP or Symfony floor, and for the same reason. An application
holding to this policy is therefore holding to one library major at a time, deliberately, rather
than to whatever a `^` happened to allow.

## Also not covered

- **`tests/`.** The test kernels, doubles and fixtures are ours. `src/Test/` is the part shipped
  for you, and it is in the table.
- **Templates.** `templates/data_collector/jwt.html.twig` renders the panel and is not a theme to
  override.
- **What a log line says.** The channel and the levels are configuration; the wording is not.
- **Anything an exception's `getMessage()` says.** `RejectionReason` is the stable thing; the
  message beside it is for a person.
- **The order of an unordered thing.** Claim providers are ordered by tag priority and that is
  covered; the order of two providers at equal priority is not.
- **Behaviour a security fix has to change**, and **behaviour that contradicted its own
  documentation**. A bug is not a contract, and neither is a vulnerability. Both are announced in
  the changelog with what to do about them.

## How something changes

1. **A minor release deprecates it**, and keeps it working. A configuration key deprecates
   through Symfony's own `setDeprecated()`, so the notice arrives at container build with the
   path that triggered it. A class, method or option deprecates through `trigger_deprecation()`
   — `symfony/deprecation-contracts` joins `require` with the first one that needs it, since
   nothing is deprecated yet.
2. **The changelog says what to use instead**, in the same release, and [`UPGRADE.md`](UPGRADE.md)
   says what an application has to do.
3. **The next major removes it.** Never a minor, never a patch.

A deprecation is a promise that the old way still works, not a warning that it is about to stop:
there is at least one full minor cycle between the notice and the removal.

## Supported versions

PHP `~8.3.0 || ~8.4.0` and Symfony `^6.4 || ^7.4 || ^8.0`, which is DEC-2 in
[`docs/plan.md`](docs/plan.md); `symfony/security-bundle` at `^6.4 || ^7.4 || ^8.0` is the hard
requirement among them, and the library underneath is `medzuch/jwt-php` at `^1.2`.

**Raising a floor is a major release** — dropping a PHP or Symfony version an application still
runs on is a break like any other, and so is moving to a new major of `medzuch/jwt-php`, whose
types this package hands you. Adding support for a new version is not, and happens whenever the
new version works.

These are the constraints in `composer.json`, and the suite fails if the two disagree: a support
window is the one thing a document like this can get wrong without anybody using it noticing.

## How this is enforced

Three of the five surfaces are read back out of this file and checked against the code, which is
the only way a document like this stays true:

| Surface | Held by | What fails |
|---|---|---|
| Classes | `tests/Unit/BackwardCompatibilityTest.php` | a class neither promised nor `@internal`; a promised class that is gone or was made internal; a class that stopped being `final`; a table row written in a shape the parser cannot read |
| Service ids | `tests/Functional/PublicSurfaceTest.php` | an id the container no longer answers, or one that answers with something other than the type its row names |
| Console commands | `tests/Functional/PublicSurfaceTest.php` | a command that is not registered where the policy says it is, or one that lost `--raw`, `--compact` or `--skip-remote` |
| Supported versions | `tests/Unit/BackwardCompatibilityTest.php` | a constraint here that `composer.json` does not require |

**The configuration tree is not**, and it is the largest surface of the five. What holds it today
is `DocumentationExamplesTest`, which compiles every example in the README and the cookbook, so a
renamed key breaks the documentation that teaches it — real coverage, and narrower than the
promise: an option no example uses could be renamed and the suite would stay green. A committed
`config:dump-reference` snapshot is the missing half, and belongs with 1.0 rather than here.

What *is* checked at container build is the other half of a configuration being wiring: every
service id a `medzuch_jwt` option names has to exist, and the refusal names the option rather
than the service.

**The authorization names are not**, either: `SCOPE_` and `is_granted_scope()` are exercised by
the functional suite, so renaming them breaks tests — but as a side effect of what those tests
are for, not because anything compares them to this file.
