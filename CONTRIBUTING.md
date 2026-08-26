# Contributing

This bundle wires a security-sensitive library into applications' authentication
path, so the bar is the same as the library's. Read this before opening a PR.

## Ground rules

1. **Thin adapter, never a re-implementation.** Crypto, parsing, claim
   validation and RFC conformance belong in
   [`medzuch/jwt-php`](https://github.com/medzuch/jwt-php). If a change needs
   new claim logic, open an issue there first and wire it here afterwards —
   a check implemented in the handler reports failures with a different
   exception type than every other check, which the `WWW-Authenticate` mapping
   then has to special-case.
2. **A configuration key is public API.** Renaming or removing one under
   `medzuch_jwt:` is a BC break; it needs a deprecation, a working alias for a
   full major, and an entry in the upgrade notes. Adding an *optional* key with
   a safe default is not.
3. **No reduction of safe defaults.** The defaults are the strict ones (§0.3 of
   [`docs/plan.md`](docs/plan.md)): explicit algorithm allowlist, `typ` pinning,
   required claims, no clock leeway, no `jku`/`x5u` following. An opt-in flag
   for a deliberately relaxed behaviour is fine when it demands explicit
   configuration; changing what omission means is not.
4. **Every configuration branch ships with a functional test** on a real test
   kernel — not just a unit test of the factory. A config tree that compiles is
   not evidence that the wired services authenticate anything.
5. **PHPStan level 9 stays green.** No baseline entries without a written
   explanation and a follow-up issue.
6. **No new required dependency.** Optional integrations (HTTP client, cache,
   Doctrine, Monolog) are wired only when configured, and their packages stay
   in `require-dev` + `suggest`.
7. **The documentation is compiled, `docs/plan.md` included.** Every ```yaml
   block under `medzuch_jwt:` in the README, the cookbook, the upgrade notes,
   the BC policy and the plan is booted into a real container by
   `DocumentationExamplesTest`, and every `medzuch_jwt.*` service id they name
   has to be one those examples build. The consequence worth knowing before you
   edit the plan: a configuration it *proposes* rather than ships cannot be
   fenced as `yaml` — fence it as `text` — or it reddens the suite on the day
   it is written.

## Comments

About a third of `src/` is comments. They are well written, which is the
problem: a second documentation set, stored where nothing checks it against the
first. The README, the cookbook, `UPGRADE.md`,
`BACKWARD-COMPATIBILITY.md` and [`docs/plan.md`](docs/plan.md) are the
documentation. Three rules keep `src/` from becoming a copy of them.

1. **Say why, not what.** The code says what it does. A comment earns its place
   only where the reason is surprising — where the next reader would otherwise
   delete the line, widen the type, or "simplify" the check. One to four lines,
   next to what they explain. The test is not "is this true?" but "would
   someone get this wrong without it?"

2. **Don't paste the documentation.** If a docblock explains a *feature* — how
   to configure it, what it is for, when to reach for it — that text already
   exists in the README, and the copy drifts the day the README is edited
   first. Name the section instead. A decision belongs in `docs/plan.md` §9 as
   a `DEC-n`; once it is written there, the comment shrinks to a pointer.

3. **Public API gets a summary; `@internal` gets the invariant.** The types
   `BACKWARD-COMPATIBILITY.md` freezes carry three to eight lines: what it is,
   how you use it, a link. An `@internal` class carries what a reviewer of the
   wiring needs — the invariant, the failure mode, the RFC line — and not the
   tutorial a user needs, because no user reads it.

**Two things this does not license.** Length is a smell, not a limit: a long
docblock that is all invariant stays, and a security rationale stays *whatever*
it costs — why naming a missing scope is not a leak, why a key's contents never
reach an exception message. Deleting one of those to hit a line count is the
failure this charter is most likely to cause. And config-node `info()` strings
are exempt in the other direction: they *are* `config:dump-reference`, so they
stay tutorial and are written for an application developer reading their own
console.

A comment that belongs, from `src/Key/KeyLoader.php`:

> A path is safe to print; the contents of an inline key are not, and a value
> that turned out to be neither is described rather than quoted.

That is an invariant the next line implements, and getting it wrong leaks key
material into an exception message — which it once did.

Not enforced by a tool, deliberately. Neither php-cs-fixer nor PHPStan can tell
a useful why from a lecture, and a line-count rule would delete the wrong half.
Reviewers apply this; a custom rule is worth discussing only after a cleanup
pass, not instead of one.

## Supported versions

PHP 8.3 and 8.4; Symfony `^6.4 || ^7.4 || ^8.0`. The CI matrix is the promise —
a constraint may only claim what the matrix tests. Version-conditional code in
`src/` is a signal to raise the floor, not to add the branch (see DEC-2 in
[`docs/plan.md`](docs/plan.md) §9).

## Workflow

1. Open an issue first for anything non-trivial.
2. Branch from `develop`: `feat/…`, `fix/…`, `docs/…`, `chore/…`.
3. Run `make qa` before pushing (from Phase 0 on — the toolchain lands with
   the skeleton).
4. Open the PR against `develop`. Reference the issue, and the feature-catalogue
   ID (C1, K3, I5 …) the change implements.
5. Feature PRs are **squash-merged**. Release PRs are not merged at all — see
   below.

A release is stamped on `develop` (`chore(release): stamp X.Y.Z`, merged like any
other PR), and `main` is then advanced by **fast-forward promotion**:
`git push origin develop:main`. No merge commit is created, `main` is always an
ancestor of `develop` by construction, and the commit `main` lands on is the one
CI already verified. A release PR is opened for visibility; GitHub marks it merged
once `main` contains its head. Tags matching `v*` are protected: they cannot be
moved or deleted, because Packagist serves them and a moved tag silently changes
what a pinned version installs.

## Commit messages

Conventional Commits:

```
feat(di): register a key resolver per configured key entry
fix(security): stop leaking the library exception message to the client
docs(config): document the audience list normalisation
test(security): cover the provider user-resolution mode end to end
chore(ci): pin actions to commit SHAs
```

Scopes in use: `di`, `security`, `issuer`, `key`, `jwks`, `command`, `config`,
`profiler`, `ci`, `docs`.

## Mutation-testing a compiler pass

Symfony's compiled container tracks configuration and class resources, not the
file a compiler pass lives in. Change `CollectVerdictsPass` or
`CheckConfiguredServicesPass` to prove a test catches it and the suite may keep
passing against a container compiled before the change.

Wipe the containers first, or the mutation you are testing never runs. The test
kernels write to two directories:

```bash
docker compose exec php rm -rf /tmp/medzuch-jwt-bundle-tests /tmp/medzuch-jwt-bundle-bare
```

`medzuch-jwt-bundle-bare` is `BareKernel`, which the configured-service checks
use because it is the one kernel that leaves the bundle's services private.

## GitHub Actions

Workflows must pin every action to a **commit SHA**, with the version as a
trailing comment. The repository enforces this; a tag reference will be
rejected before the workflow runs.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not open a public issue.
