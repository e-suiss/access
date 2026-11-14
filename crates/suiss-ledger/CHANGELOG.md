# Changelog

## 0.7.3

Released with `esuiss-access-kernel` 0.7.3 (Kernel 0.7.0 semantics, unchanged). No API change from 0.7.0; 0.7.0, 0.7.1 and 0.7.2 were never published.

## 0.7.2

Never published: the v0.7.2 release run stopped at a test that SoftHSM 2.6.1 failed under concurrency (OP-159 m.33). No API change from 0.7.0.

## 0.7.1

Never published: the v0.7.1 release run stopped at its test job's time limit before anything was published (OP-159 m.30). No API change from 0.7.0.

## 0.7.0

Never published: the v0.7.0 release run stopped at its FIPS image build before anything was published (OP-159 m.28). Prepared with `esuiss-access-kernel` 0.7.0 (Kernel 0.7.0 semantics: ML-DSA-44/65/87 verification through the `Backend` port, the hybrid signature policy and the `hybrid-artefact` carrier, PQ anchors and RA-7 acceptance of retired-algorithm artefacts, the superseded cause and inclusion evidence over a record's committed `artifacts`, root-term witness and replica sets, holding terms on meta-actions, the new-payee floor and `audit_export` as a CT1 read). Public structs and enums gained fields and variants, so the minor version moves. 0.6.0 was never published.

### Added

- The post-quantum cosign wire types `PqCosignRequest` and `PqCosign` for the ML-DSA re-anchor cosign.

## 0.6.0

Never published: the v0.6.0 release run stopped at its test job before anything was published (OP-159 m.24). Prepared with `esuiss-access-kernel` 0.6.0 (Kernel 0.6.0 semantics: catalog 8, `domain_handover` and `domain_recover` with the recovery entry and rollback guard, the pre-recovery nonce closure, superseded-at bindings, version activation and algorithm retirement, self-anchor narrowing, conditional `anchor_transfer`, DistinctSurface surface paths, and the witness head the rollback guard reads). The Kernel's public structs gained fields, so the minor version moves. 0.5.0 was never published.

### Added

- RFC 9162 inclusion and consistency proof builders, C2SP hash tiles and the add-checkpoint body, the checkpoint `Cadence`, the witness `LogState` (base check, equivocation, fence), and the Replica Mirror frames with the signed replica ack and a `Follower`.

## 0.5.0

Never published (OP-158 m.21 (d)). Prepared with `esuiss-access-kernel` 0.5.0 (Kernel 0.4.1 semantics: catalog 7 types, `policy.set` structural polarity, the closed `derived.*` values, policy defaults, compatibility mappings, `DistinctSurface` and the actor Party exclusion, and a Mandate decided by its window, while-conditions, budget and pin). The Kernel's public structs gained fields, so the minor version moves.

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
