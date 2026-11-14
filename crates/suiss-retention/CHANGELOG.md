# Changelog

## 0.7.3

Released with `esuiss-access-kernel` 0.7.3 (Kernel 0.7.0 semantics, unchanged). No API change from 0.7.0; 0.7.0, 0.7.1 and 0.7.2 were never published.

## 0.7.2

Never published: the v0.7.2 release run stopped at a test that SoftHSM 2.6.1 failed under concurrency (OP-159 m.33). No API change from 0.7.0.

## 0.7.1

Never published: the v0.7.1 release run stopped at its test job's time limit before anything was published (OP-159 m.30). No API change from 0.7.0.

## 0.7.0

Never published: the v0.7.0 release run stopped at its FIPS image build before anything was published (OP-159 m.28). Prepared with `esuiss-access-kernel` 0.7.0 (Kernel 0.7.0 semantics: ML-DSA-44/65/87 verification through the `Backend` port, the hybrid signature policy and the `hybrid-artefact` carrier, PQ anchors and RA-7 acceptance of retired-algorithm artefacts, the superseded cause and inclusion evidence over a record's committed `artifacts`, root-term witness and replica sets, holding terms on meta-actions, the new-payee floor and `audit_export` as a CT1 read). Public structs and enums gained fields and variants, so the minor version moves. 0.6.0 was never published.

## 0.6.0

Never published: the v0.6.0 release run stopped at its test job before anything was published (OP-159 m.24). Prepared with `esuiss-access-kernel` 0.6.0 (Kernel 0.6.0 semantics: catalog 8, `domain_handover` and `domain_recover` with the recovery entry and rollback guard, the pre-recovery nonce closure, superseded-at bindings, version activation and algorithm retirement, self-anchor narrowing, conditional `anchor_transfer`, DistinctSurface surface paths, and the witness head the rollback guard reads). The Kernel's public structs gained fields, so the minor version moves. 0.5.0 was never published.

- `Schedule::one_default`: the Ek C C.3.7 defaults of the Suiss One classes; `Class::is_user_keyed`, `Class::shredded_with_account`, `OneData` and `export_class` for the One mappings.
- `user_keyed`: recovery path setup and KEK recovery, and the erasure plan of the user-keyed domain (record, class, account), with device copies destroyed on reconnect and holds that suspend destruction without making anything readable.

## 0.5.0

Never published (OP-158 m.21 (d)). Prepared with `esuiss-access-kernel` 0.5.0 (Kernel 0.4.1 semantics: catalog 7 types, `policy.set` structural polarity, the closed `derived.*` values, policy defaults, compatibility mappings, `DistinctSurface` and the actor Party exclusion, and a Mandate decided by its window, while-conditions, budget and pin). The Kernel's public structs gained fields, so the minor version moves.

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

First release: retention classes, `Schedule`, `Hold`, `may_destroy` and the Work class defaults.
