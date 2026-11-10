# Changelog

## Unreleased

- Feature `doorbell`: the NATS JetStream doorbell. `Ring` and its CBOR payload `{domain, pos, idx}`, the durability `Gate`, the `Bell` trait, and a small NATS client (`client::Publisher` with the JetStream publish acknowledgement, `client::Listener`, `publish`, `listen`) over TLS 1.3 with a client certificate. Feature `testing`: an in-process NATS twin and a test PKI.

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

### Added

- `port`: the `LogStore` storage port and `commit`, one plan–append–advance cycle with the step-down and abandon rules.
- `fence`: the durability fence and the outbox cursor.
- `checkpoint`: `of_head` builds a C2SP `tlog-checkpoint` from the head; `Publication` enforces mirror before witness.
- `replica`: `Follower` checks mirrored leaves against checkpoints and their consistency.
- `time::check_against_witness`.
- `sequencer::Params`: the batch limit, which can only be lowered; `Sequencer::lead_with`.

### Changed

- `PlanError` and `TimeError` are `#[non_exhaustive]`.
- `Sequencer::lead` is no longer `const`.

## 0.1.1

First release: Merkle frontier, sequencer and trusted time.
