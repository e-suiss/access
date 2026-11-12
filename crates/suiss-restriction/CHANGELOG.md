# Changelog

## 0.6.0

Released with `esuiss-access-kernel` 0.6.0 (Kernel 0.6.0 semantics: catalog 8, `domain_handover` and `domain_recover` with the recovery entry and rollback guard, the pre-recovery nonce closure, superseded-at bindings, version activation and algorithm retirement, self-anchor narrowing, conditional `anchor_transfer`, DistinctSurface surface paths, and the witness head the rollback guard reads). The Kernel's public structs gained fields, so the minor version moves. 0.5.0 was never published.

## 0.5.0

Never published (OP-158 m.21 (d)). Prepared with `esuiss-access-kernel` 0.5.0 (Kernel 0.4.1 semantics: catalog 7 types, `policy.set` structural polarity, the closed `derived.*` values, policy defaults, compatibility mappings, `DistinctSurface` and the actor Party exclusion, and a Mandate decided by its window, while-conditions, budget and pin). The Kernel's public structs gained fields, so the minor version moves.

### Added

- `@breakglass_exempt` on a plain blocking `forbid` rule (a rule with `@require` fails to compile with `policy-exempt-not-blocking`), `Engine::evaluate_as` that lifts a matching exempt rule for a break-glass request, and `PolicyView.exempt`.

## 0.4.0

No changes; released with `esuiss-access-kernel` 0.4.0 (intent plan reference, parameter provenance and Mandate origin sets; `disclose`/`declassify` core classes; runtime and effect attestation, executor control and workload binding Claim classes; Approval Act surface class and evidence; action reversibility). The Kernel's public structs gained fields, so the minor version moves.

## 0.3.2

No changes; released with `esuiss-access-kernel` 0.3.2 (causal-bound allowances in the Genesis policy; an organization Party has no Instance, C6).

## 0.3.1

No changes; released with `esuiss-access-kernel` 0.3.1 (explanation scopes and the contribute intent in the Kernel).

## 0.3.0

No changes; released with `esuiss-access-kernel` 0.3.0.

## 0.2.6

No changes; released with `esuiss-access-kernel` and published from CI with trusted publishing.

## 0.2.5

No changes; released with `esuiss-retention`.

## 0.2.4

No changes; released with `esuiss-crypto`.

## 0.2.3

No changes; released with `esuiss-crypto`.

## 0.2.2

No changes; released with `esuiss-sandbox`.

## 0.2.1

### Changed

- `Limits` fields are private. Start from `Limits::default()` and lower one value at a time with `Limits::narrowed(Narrow::…)`; asking for a wider value is `WiderLimit`.
- `CompileError` is `#[non_exhaustive]` and has a stable `code()`.

## 0.1.1

First release.
