# Security Policy

## Supported versions

| Version | Status |
| ------- | ------ |
| 0.x     | Pre-release. Best-effort fixes; no guarantees. |
| 1.x     | Full security support once released. |

## Reporting a vulnerability

**Do not open a public GitHub issue.** Use GitHub's private vulnerability
reporting:

→ **[Report a vulnerability](https://github.com/medzuch/jwt-bundle/security/advisories/new)**

(Also reachable from the repo's *Security → Advisories → Report a
vulnerability* button.)

**No GitHub account, or private reporting unavailable?** Use the contact
details on [my GitHub profile](https://github.com/medzuch) as the fallback
channel. Either way, please keep the details out of any public place — issues,
discussions, social media — until a fix is released.

Include:

- A description of the issue.
- A proof-of-concept or steps to reproduce.
- The affected version(s), and the Symfony and PHP versions involved.
- Any suggested mitigation.

This is a one-person project. I'll acknowledge reports as soon as I see them
and fix when I can — usually quickly for anything high-severity, but there are
no guaranteed timelines while the bundle is pre-1.0. If you don't hear back
within a week, feel free to nudge in the advisory thread. :)

## Disclosure

We follow **coordinated disclosure**. Once a fix is released, we will:

1. Publish a GitHub Security Advisory.
2. Credit the reporter (unless they prefer to stay anonymous).
3. Request a CVE ID where appropriate.

## Scope

This package is an adapter: it decides *which* checks run and *what a failure
means to Symfony*, while the checks themselves live in `medzuch/jwt-php`.
The split matters for where a report belongs.

In scope:

- Authentication bypass through the token handler — a token accepted that the
  configured consumer should have rejected.
- Configuration that silently disables a check: a key, a default, or a
  normalisation step that turns an advertised guarantee (issuer, audience,
  algorithm allowlist, `typ` pinning, required claims) into a no-op.
- Key material reaching somewhere it should not: the profiler, logs, exception
  messages, `debug:container` parameter dumps, or a JWKS response.
- Revocation bypass — a token that survives a denylist entry for its `jti`.
- Wiring that binds a consumer to the wrong firewall, or a firewall to a
  consumer with weaker policy than configured.

Out of scope (report upstream):

- Cryptographic correctness, parser behaviour, and claim validation — those are
  [`medzuch/jwt-php`](https://github.com/medzuch/jwt-php/security/policy).
- Vulnerabilities in Symfony itself — report to
  [Symfony](https://symfony.com/security).
- Applications that configure the bundle unsafely in ways the documentation
  warns against, or that bypass the wired services and call the library
  directly.
