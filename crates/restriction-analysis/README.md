# esuiss-restriction-analysis

Control-plane analysis of Access restriction policy changes: Cedar `SymCC` with a pinned cvc5
running as a separate, sandboxed process. It never runs on the request path and never in the
Kernel.

## What it answers

- `analyze(old, new)` — the gate before a `policy.set` is applied: `Equivalent`, `Narrowing`,
  `Widening` (with a counterexample when the solver gives one) or `MayError`. Any failure,
  including a time limit, is an `AnalysisError`, and the change must not be applied.
- `compare(old, new)` — the preview question "did authority change?", asked in both directions:
  `Equivalent`, `Narrowing` (authority shrank), `Widening` (authority grew), `Incomparable`
  (grew somewhere and shrank elsewhere) or `MayError`. Every failure, a time limit included, is
  `Unknown`; a preview never reads a missing answer as "equivalent".

Both take policies written against the same schema and refuse sets outside the restriction
rules (forbid-only, no `permit`). A changed `@require` reference is reported as widening before
the solver runs.

Role versions are not Cedar: a role is a Named `AuthoritySet`, and comparing two versions is a
closed-algebra question the Kernel decides exactly (`subsumes` both ways), without a solver.

## Solver

- The cvc5 build is pinned by version and sha256 per platform in `supply-chain/cvc5.toml`; the
  binary is hashed again before every run and a mismatch never starts.
- Each run is confined by the caller's sandbox profile (`suiss-sandbox` solver profile on Linux).
- Two time limits: one per solver query (passed to cvc5 as `--tlimit-per`) and one for the whole
  analysis. Defaults are 60 s per query and 600 s in total; previews should pass shorter ones.

## Measurements

The solver-backed tests run only on Linux with the pinned cvc5 (`just smt-test`). The
`compare_answers_each_relation_and_reports_its_time` test prints the wall time of each relation
for the four-policy reference set (`equivalent`, `narrowing`, `widening`, `incomparable`).

| Case | Where | Wall time |
|---|---|---|
| Reference set, each relation | Linux CI, pinned cvc5 | not yet recorded |

The often-quoted figure of about 75 ms per comparison is **unverified**: it has not been measured
on this code. Until a CI run records it here, size preview time limits by measurement, not by
that figure. On macOS no cvc5 is pinned and every solver run fails closed.
