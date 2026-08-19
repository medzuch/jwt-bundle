## What and why

<!-- What changes, and what problem it solves. Link the issue. -->

Closes #

## Feature catalogue

<!-- The ID(s) from docs/plan.md §3 this implements, or "n/a". -->

## Checklist

- [ ] `make qa` passes locally *(from Phase 0 on — the toolchain lands with the skeleton)*
- [ ] Functional test on a real kernel covers any new configuration branch
- [ ] Configuration impact stated below
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Actions (if touched) pinned to commit SHAs
- [ ] If key material is touched: it cannot reach the profiler, logs, exception
      messages, `debug:container` output or a JWKS response (K9)

## Configuration impact

<!--
One of:
  - none
  - new optional key(s), safe default — name them
  - BC break under `medzuch_jwt:` — name the key, the deprecation path, and the
    alias that keeps the old spelling working (see CONTRIBUTING.md, rule 2)
-->
