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

## Supported versions

PHP 8.3 and 8.4; Symfony `^6.4 || ^7.4 || ^8.0`. The CI matrix is the promise —
a constraint may only claim what the matrix tests. Version-conditional code in
`src/` is a signal to raise the floor, not to add the branch (see D2 in
[`docs/plan.md`](docs/plan.md) §9).

## Workflow

1. Open an issue first for anything non-trivial.
2. Branch from `develop`: `feat/…`, `fix/…`, `docs/…`, `chore/…`.
3. Run `make qa` before pushing.
4. Open the PR against `develop`. Reference the issue, and the feature-catalogue
   ID (C1, K3, I5 …) the change implements.
5. Feature PRs are **squash-merged**; release and back-merge PRs use a **merge
   commit**, so `main` and `develop` never diverge permanently.

Releases go `develop → main` as `chore(release): stamp X.Y.Z`, then `main` is
back-merged into `develop`. Tags matching `v*` are protected: they cannot be
moved or deleted, because Packagist serves them and a moved tag silently
changes what a pinned version installs.

## Commit messages

Conventional Commits:

```
feat(di): register a key resolver per configured key entry
fix(security): stop leaking the library exception message to the client
docs(config): document the audience list normalisation
test(functional): cover the provider user-resolution mode end to end
chore(ci): pin actions to commit SHAs
```

Scopes in use: `di`, `security`, `issuer`, `key`, `jwks`, `command`, `config`,
`profiler`, `ci`, `docs`.

## GitHub Actions

Workflows must pin every action to a **commit SHA**, with the version as a
trailing comment. The repository enforces this; a tag reference will be
rejected before the workflow runs.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not open a public issue.
