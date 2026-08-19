# medzuch/jwt-bundle

A Symfony bundle wiring [`medzuch/jwt-php`](https://github.com/medzuch/jwt-php) into Symfony
applications: **issuing** JOSE tokens (RFC 9068 access tokens, OIDC ID tokens, custom JWS/JWE)
and **verifying** them through Symfony's native Security stack — the `access_token` firewall
authenticator, DI, configuration, console and profiler.

Works for any of these roles, in any combination:

- **Resource server** — verify bearer tokens on an API firewall.
- **Authorization server** — mint short-lived access tokens on login.
- **OIDC relying party** — verify a third-party IdP's tokens via cached, rotation-aware JWKS.
- **Service-to-service** — machine tokens between your own services.

**Status: design only.** No bundle code yet — see [`docs/plan.md`](https://github.com/medzuch/jwt-bundle/blob/main/docs/plan.md) for the
full design, the feature catalogue with priority tiers, and the phased roadmap.

Requires PHP 8.3 / 8.4 and Symfony 6.4 LTS, 7.4 LTS or 8.x (planned).

## License

MIT — see [LICENSE](LICENSE).
