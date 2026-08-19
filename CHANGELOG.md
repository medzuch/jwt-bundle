# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Configuration keys under `medzuch_jwt:` are public API: a rename or removal is
a breaking change and is recorded here with its deprecation path, the same way
a class or method signature would be.

## [Unreleased]

Nothing released yet — the package is in Phase 0 (skeleton). See
[`docs/plan.md`](docs/plan.md) §7 for the roadmap.

### Added

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
