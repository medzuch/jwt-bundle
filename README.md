# medzuch/jwt-bundle

A Symfony bundle wiring [`medzuch/jwt-php`](https://github.com/medzuch/jwt-php) into Symfony
applications for JWT issuance (login) and verification (API authentication), via Symfony's
native `access_token` firewall.

**Status: design only.** No bundle code yet. First intended consumer is
[`home-budget`](../home-budget) (see its [ADR-010](../home-budget/docs/adr/010-medzuch-jwt-bundle-over-lexik.md)),
whose auth requirements shaped the plan below.

See [`docs/plan.md`](docs/plan.md) for the full design and phased roadmap.

## License

MIT — see [LICENSE](LICENSE).
