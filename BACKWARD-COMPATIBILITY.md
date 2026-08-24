# Backward compatibility

What this package promises not to break, and what it reserves the right to change.

**The promise starts at 1.0.** Until then the surface is young enough that a minor release may
move it, which is what every release note so far has said. What is written below is the shape
1.0 freezes; [`UPGRADE.md`](UPGRADE.md) is where a release says what it asks of you, and
[`CHANGELOG.md`](CHANGELOG.md) what it changed.

From 1.0 the package follows [semantic versioning](https://semver.org): the public surface below
changes only in a major release, and only after a minor release has deprecated what it changes.

## The public surface

Four kinds of thing, and they are not all promised in the same way.

### Configuration

Everything under the `medzuch_jwt` root key: the section names, the option names, their defaults
and what a value means. `config:dump-reference medzuch_jwt` prints the tree you have, generated
from the bundle rather than copied by hand.

A configuration that boots on 1.x keeps booting on every later 1.x, and keeps meaning the same
thing. New options may be added — with a default that changes nothing — and existing ones may be
deprecated, but neither costs an application a rewrite.

### Service ids

The ids the documentation tells you to name, all of them derived from a name you chose:

| Id | What names it |
|---|---|
| `medzuch_jwt.handler.<consumer>` | a firewall's `access_token.token_handler` |
| `medzuch_jwt.entry_point.<consumer>` | a firewall's `entry_point` |
| `medzuch_jwt.access_denied.<consumer>` | a firewall's `access_denied_handler` |
| `medzuch_jwt.denylist.<consumer>` | your code, to revoke a token |
| `medzuch_jwt.issuer.<issuer>` | your code, to mint one |
| `medzuch_jwt.login.<issuer>` | an authenticator's `success_handler` |
| `medzuch_jwt.id_token.<registration>` | your code, to verify an ID token |
| `medzuch_jwt.token_extractor.<extractor>` | a firewall's `access_token.token_extractors` |
| `medzuch_jwt.key.<key>.signing`, `.verification` | your code, for a key you configured |
| `medzuch_jwt.jwks_controller` | a route serving the JWK Set |

A key answers by role because only one role may exist: an entry given a public half alone has a
`.verification` service and no `.signing` one. The bare `medzuch_jwt.key.<key>` is where the
half you configured is built and keeps working, but it is not in the table — which of the two it
means depends on the entry.

An id that exists on 1.x resolves to a service of the same type on every later 1.x. What the
*class* behind it is called is not part of that: `medzuch_jwt.handler.api` will answer
`AccessTokenHandlerInterface`, and which of our classes implements it is ours to change.

Any other id — anything not in that table, and anything with `.profile`, `.key_set` or a similar
suffix naming a part rather than a whole — is wiring, and moves without notice.

**Three are deliberately absent although they look like they belong**: `medzuch_jwt.consumer.<consumer>`,
the verifier the handler wraps; `medzuch_jwt.remote_jwks.<set>`, the resolver behind it; and
`medzuch_jwt.clock`, which every dated decision reads. All three are stable and none is
documented as something to name, and promising an id nobody was told to use freezes the type
behind it for no reader. Each joins the table as soon as the documentation gives it a use —
verifying a token outside a firewall being the obvious one.

### Console commands

`jwt:key:generate`, `jwt:token:create`, `jwt:token:inspect`, `jwt:jwks:dump` and
`jwt:config:check`: the names, their arguments and options, and their exit statuses. A script
that gates a deploy on `jwt:config:check` keeps working.

What they *print* is not covered. Tables, colours and wording are for a person reading a
terminal; `--raw` and `--compact` exist because a script needs something stable, and those two
are.

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
| `Security\User\ProvidesScopes` | — | — | — | **yes** |
| `Revocation\TokenDenylistInterface` | — | — | — | **yes** |
| `Oidc\IdTokenVerifier` | inject it | yes | no | — |
| `DataCollector\JwtDataCollector` | read it, in a panel of your own | its readers | no | — |
| `Test\TestTokenFactory` | use it in your tests | yes | no | — |
| `Test\AssertsBearerChallenges` | use it in your tests | yes | — | — |

Every class in this package is `final`, so "extend it: no" is enforced rather than asked, and the
suite keeps it that way. What the table adds is the distinction `final` cannot make:

- **An interface you implement** is the strictest promise here. Adding a method to
  `TokenClaimProviderInterface`, `JwtUserFactoryInterface`, `ProvidesScopes` or
  `TokenDenylistInterface` breaks every implementation, so it happens in a major release only.
- **A class you receive** — an event, an `IssuedToken`, a `TokenIssuance` — may gain methods and
  readable properties in a minor release. Nothing you wrote against the old shape stops working;
  you simply have more to read.
- **`RejectionReason` may gain cases.** It is a vocabulary for a dashboard, and a new kind of
  refusal has to be nameable. `match` on it without a `default` and a new case is a fatal error
  — which is a good reason to write the `default`, and the reason this is said here rather than
  discovered.
- **`JwtDataCollector`'s mutators are not yours.** The tracing decorator writes to it; an
  application reads it. The read side is what the table covers.
- **`AssertsBearerChallenges` is a trait**, so its methods land in your test case. A new
  assertion is additive unless you already have a method by that name, which is the one way
  adding to it can break you — new names are chosen to be unlikely, not guaranteed.

**Everything else in `src/` is internal**, marked `@internal` and free to change in any release —
the handlers, the extractors, the voter, the resolvers, the key loader, the commands' classes,
the compiler pass, the controller. They are reachable by service id or by command name, and those
are covered above; the classes are not.

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
[`docs/plan.md`](docs/plan.md).

**Raising a floor is a major release** — dropping a PHP or Symfony version an application still
runs on is a break like any other. Adding support for a new one is not, and happens whenever the
new version works.

## How this is enforced

`tests/Unit/BackwardCompatibilityTest.php` reads the table above and compares it to `src/`. A
class that is neither in the table nor marked `@internal` fails the suite, and so does a table
row naming a class that no longer exists. The policy and the code cannot drift apart without
somebody noticing, which is the only way a document like this stays true.
