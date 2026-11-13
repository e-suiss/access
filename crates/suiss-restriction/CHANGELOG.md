# Changelog

## 0.7.0

Released with `esuiss-access-kernel` 0.7.0 (Kernel 0.7.0 semantics: ML-DSA-44/65/87 verification through the `Backend` port, the hybrid signature policy and the `hybrid-artefact` carrier, PQ anchors and RA-7 acceptance of retired-algorithm artefacts, the superseded cause and inclusion evidence over a record's committed `artifacts`, root-term witness and replica sets, holding terms on meta-actions, the new-payee floor and `audit_export` as a CT1 read). Public structs and enums gained fields and variants, so the minor version moves. 0.6.0 was never published.

## 0.6.0

Never published: the v0.6.0 release run stopped at its test job before anything was published (OP-159 m.24). Prepared with `esuiss-access-kernel` 0.6.0 (Kernel 0.6.0 semantics: catalog 8, `domain_handover` and `domain_recover` with the recovery entry and rollback guard, the pre-recovery nonce closure, superseded-at bindings, version activation and algorithm retirement, self-anchor narrowing, conditional `anchor_transfer`, DistinctSurface surface paths, and the witness head the rollback guard reads). The Kernel's public structs gained fields, so the minor version moves. 0.5.0 was never published.

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
