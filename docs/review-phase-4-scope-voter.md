# Review: `feat/phase-4-scope-voter`

Compared against `develop` (three commits, 15 files).

**Verdict:** safe to merge from a correctness and security standpoint. No authorization bypass. Remaining notes are docs accuracy, interop, and test coverage — not blockers.

The design is sound: scopes stay a separate namespace, the voter is wired the way Symfony expects, and the earlier review items (non-string `scope` must not 500, one `voteOnAttribute` signature across 6.4/7.4/8, `willBeAvailable()`, stacked docblocks) are actually fixed.

## What works

- `SCOPE_*` is answered only from `ProvidesScopes`, so a role and a token grant stay different statements.
- `JwtUser::scopes()` uses `get()` plus a string check, so `"scope": ["reports.read"]` is a 403, not a 500 during authorization.
- Matching is exact (`reports.readonly` does not satisfy `reports.read`); empty pieces from extra spaces are dropped.
- `voteOnAttribute(..., mixed $vote = null)` is a real cross-version compromise; naming `Vote` would break 6.4.
- `is_granted_scope()` compile and evaluate paths are both tested, without pinning `AuthorizationCheckerInterface`.
- Provider mode with an `InMemoryUser` is refused, which matches the “store is the authority” rule.

## Findings

| Severity | Location | Finding |
|---|---|---|
| Low | `README.md` / `docs/plan.md` | **Provider mode is overstated.** The voter denies when the user is not `ProvidesScopes`, not because the mode is `provider`. A store-loaded `User` that implements the interface would get `SCOPE_*` grants. That is a useful escape hatch; the README says every such check is refused. |
| Suggestion | `JwtUser::scopes()` vs `ClaimRoles` | **List-valued `scope` still grants nothing.** Spec-correct (RFC 6749 / 9068), and you already chose 403 over 500. `ClaimRoles` still accepts a JSON list. Issuers that send `"scope": ["reports.read"]` will authenticate, map roles if configured that way, and fail every `SCOPE_*` check. Worth accepting a list of strings the same way `ClaimRoles` does, or saying so in the README. |
| Suggestion | `JwtUser::scopes()` | **Claim name is hardcoded to `scope`.** Entra ID uses `scp`. Custom factories can map that; `claims` mode cannot. Fine for RFC 9068; mention it if Azure is in scope for 1.0. |
| Low | `tests/Functional/UserModeTest.php` | **Custom mode is not exercised through the voter.** The factory’s `groups` → `scopes()` mapping is asserted on the user object. The README promise (`#[IsGranted('SCOPE_*')]` in custom mode) never hits `/api/scoped`. |

## Test gaps (not bugs)

- A token with `reports.read` plus other scopes should still be allowed; only the exact-match case is covered.
- Bare `SCOPE_` is documented as denied and has no test.
- `SecuredKernel` now always registers `^/api/scoped` → `SCOPE_reports.read` as the first `/api` rule. First-match means that path does not also require `IS_AUTHENTICATED_FULLY`. Harmless for these tests; a bit of coupling for every other `SecuredKernel` test.

## Unanimous / consensus

The DI comment is accurate: under the default **affirmative** strategy this voter cannot veto another grant. Under **unanimous**, a `SCOPE_*` check on a user that is not `ProvidesScopes` is a veto. That belongs in the README next to “nothing to switch off”, because that sentence is only true for the default strategy.
