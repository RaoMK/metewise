# Changelog

All notable changes to metewise are documented here. Versioning follows
[Semantic Versioning](https://semver.org): a **new feature bumps the minor
version**, a bug fix bumps the patch version, and a breaking change bumps the
major version.

## [0.2.0] — 2026-08-31

### Added
- **Write-side BOLA probing.** metewise can now test whether another user can
  *modify* or *delete* your objects, not just read them.
  - `--write` tests `PUT`/`PATCH` (`MUTATE` tier): snapshots the object as the
    owner, has the attacker write a marked sentinel, verifies the change, then
    restores the original and re-verifies the restore.
  - `--allow-destructive` tests `DELETE` (`DESTRUCTIVE` tier) against a freshly
    **seeded throwaway** object learned from an observed `POST` — never real data.
  - Money/message endpoints (`/pay`, `/charge`, `/email`, `/webhook`, …) are
    denylisted as a `FORBIDDEN` tier and never probed.
- `scan-har` accepts **multiple HAR files** (one capture per user).
- Beginner-friendly README and a terminal-demo image (`docs/demo.svg`).

## [0.1.0] — 2026-08-30

### Added
- Initial release: read-side BOLA/IDOR regression fuzzer.
- Four-corner oracle (deny / anon-public / owner-baseline) that proves leaks by
  matching stable victim leaf values, handles soft-403s and public resources,
  and marks a run INVALID when an owner token is dead.
- HAR ingest with principal attribution, identifier discovery, URL templating,
  and cross-principal probe planning.
- `scan-har` and `scan` CLI subcommands with CI-shaped exit codes.
- MIT license; GitHub Actions CI on Python 3.10–3.13.

[0.2.0]: https://github.com/RaoMK/metewise/releases/tag/v0.2.0
[0.1.0]: https://github.com/RaoMK/metewise/releases/tag/v0.1.0
