# Contributing to Access

Thank you for your interest in Access. This guide explains how to set up a development environment, the rules code must follow, and how changes get merged.

Access is pre-alpha: the specification is largely settled and the implementation is at its foundation stage. Nothing is stable yet, and the rules below are already binding.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md).

## Development environment

You need [rustup](https://rustup.rs) (the toolchain version is pinned in `rust-toolchain.toml` and installed automatically), [`just`](https://github.com/casey/just), [`cargo-nextest`](https://nexte.st) and Docker with Compose v2. Then (OP-69):

```sh
git clone https://github.com/e-suiss/access.git
cd access
just dev    # starts the local services and waits until they are healthy
just test   # runs the same tests as CI on pull requests
```

`just dev` starts these services with Docker Compose (`deploy/compose/`). Every port is published on `127.0.0.1` only; if one is taken, override it with the matching `ACCESS_DEV_*_PORT` variable.

| Service | Purpose | Address |
| --- | --- | --- |
| PostgreSQL 18 | Database `access`; runtime role `access_app` (no `DELETE`/`TRUNCATE`), owner role `access_owner` | `127.0.0.1:5432` |
| NATS (JetStream) | Messaging | `127.0.0.1:4222`, monitoring `:8222` |
| SoftHSM 2 (PKCS#11) | Local HSM/KMS; token `access-dev` | `just dev-hsm --show-slots` |
| Mailpit | Captures outgoing e-mail; nothing is delivered | `http://127.0.0.1:8025`, SMTP `:1025` |
| OpenTelemetry Collector | Receives OTLP traces, metrics and logs | `127.0.0.1:4317` (gRPC), `:4318` (HTTP) |
| Jaeger, Prometheus, Grafana | Traces, metrics and dashboards | `http://127.0.0.1:16686`, `:9090`, `:3300` |

The credentials in `deploy/compose/compose.yaml` are synthetic, local-only values. Never put a real secret in the local environment, and never commit a `.env` file.

Other commands:

- `just check`: the same checks as CI (format, lints, repository rules, dependency policy).
- `just dev-down`: stops the services; the database volume is kept.
- `just db-reset`: recreates the database from scratch and loads the synthetic seed data.
- `just psql`: a `psql` shell as the runtime role.
- `just image`: builds the `access-server` container image (distroless, non-root).
- `just mkcert <host>`: a locally trusted certificate for a custom domain. WebAuthn works on `localhost` without one.
- `just bench`: benchmarks.
- `bacon`: rebuilds and re-runs clippy on every save; `bacon test` does the same for the tests.

A [dev container](.devcontainer/devcontainer.json) with the same toolchain is available if you prefer one; run `just dev` on the host.

Performance work follows one rule: correctness first, then measurement, then optimization. Unmeasured optimizations are not accepted, and a security check is never weakened for speed (OP-72).

There is no "development mode": security controls are never disabled locally. Local equivalents (SoftHSM (PKCS#11), Mailpit) replace production components instead (TI-9).

## Code rules (summary)

The full rules are in the project specification: repository layout (OP-62), architecture patterns (OP-63), code quality (OP-64), API (OP-65), data layer (OP-66), observability (OP-67), testing (SA-59) and supply chain (§14.7).

- Code, comments, commit messages and pull requests are in English.
- `rustfmt` and the workspace lints apply; warnings are errors in CI.
- No `unsafe` outside the allowlisted crates; every `unsafe` block has a `// SAFETY:` comment.
- No panics on the request path; arithmetic is checked.
- Every identifier has its own type (`GrantId`, `TenantId`, ...); never a bare `String` or `Uuid`.
- An authority decision (ALLOW / DENY / REQUIRE_ACTION) is a result, not an error.
- Secrets and personal data are never logged.
- SQL lives only in the `store` crate; no ORM.
- Code that implements a specification rule names its ID in a comment, e.g. `// INV-2: single write path`.
- `TODO` comments must reference an issue.
- Tests are named after behavior (`deny_when_grant_expired`); flaky tests are quarantined, never retried until green.

## Branches, commits and pull requests

- Work on a short-lived branch: `feat/...`, `fix/...`, `docs/...`.
- Commit messages and pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/), with the crate or area as scope: `feat(identity-oauth): add PAR support`.
- Commits must be signed.
- Keep pull requests small (target: under 400 changed lines) and fill in the pull request template.
- Pull requests are merged with squash merge only, after CI passes and a maintainer reviews and merges.
- Changes to security-sensitive paths (Kernel, crypto, store, signer, authentication flows, migrations) need a short threat assessment in the pull request.
- Pull requests that add or change a specification decision carry the `decision` label and update the decision register (OP-70).

## Good first issues

Issues labeled `good first issue` are a good place to start.

## Code of conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
