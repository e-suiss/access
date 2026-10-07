# Contributing to Access

Thank you for your interest in Access. This guide explains how to set up a development environment, the rules code must follow, and how changes get merged.

The project is at the specification stage; implementation has not started. The rules below are already binding and are defined in the specification under [`docs/spec/`](docs/spec/README.md) (written in Turkish). An English overview is in [`docs/overview.md`](docs/overview.md).

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md).

## Development environment

Once the codebase exists, getting started will take three steps (OP-69):

```sh
git clone https://github.com/e-suiss/access.git
cd access
just dev    # starts PostgreSQL, NATS, SoftHSM, a KMS emulator, Mailpit and observability
just test   # runs the same tests as CI on pull requests
```

Other commands: `just check` (the same checks as CI), `just gen` (regenerate OpenAPI, Protobuf, sqlx metadata and Kernel bindings), `just db-reset`, `just bench` (benchmarks) and `just profile` (profiling with `samply`/`cargo flamegraph`, `tokio-console`, `dhat`).

Performance work follows one rule: correctness first, then measurement, then optimization. Unmeasured optimizations are not accepted, and a security check is never weakened for speed (OP-72).

There is no "development mode": security controls are never disabled locally. Local equivalents (SoftHSM, a KMS emulator, Mailpit) replace production components instead (TI-9).

## Code rules (summary)

The full rules are in the specification: repository layout (OP-62), architecture patterns (OP-63), code quality (OP-64), API (OP-65), data layer (OP-66), observability (OP-67), testing (SA-59) and supply chain (§14.7).

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
