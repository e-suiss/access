# Changelog

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

### Changed

- The lockdown sets `RLIMIT_CORE` to zero; a failure reports `Step::CoreLimit`.
- The signer profile allows filesystem writes and `renameat`, kept inside its key vault by Landlock.

## 0.2.3

No changes; released with `esuiss-crypto`.

## 0.2.2

First release on crates.io.

## 0.2.1

First release as a shared crate. It was `access-sandbox`; the library is now `suiss_sandbox`.
