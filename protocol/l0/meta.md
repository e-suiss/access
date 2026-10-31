# L0 Meta-actions

Status: first draft, core track version 1. Not yet adopted.

A meta-action is an Exercise that changes authority state. Apart from Genesis, it is the only way authority state changes. This part defines the meta-action payloads, the identifiers they create, the state they write and the authority each one needs. The data model is in [`kernel.cddl`](../../conformance/cddl/kernel.cddl): `meta-payload`, `genesis-fields`, the `*-state` rules and `exercise-basis`.

## 1. Payload and identifiers

<a id="L0-META-1"></a>**L0-META-1. Core actions.** A meta-action is an intent whose action has namespace `access` and one of the names of `meta-payload`: `anchor_create`, `anchor_transfer`, `anchor_amend`, `anchor_retire`, `party_register`, `party_depart`, `instance_create`, `instance_rekey`, `instance_terminate`, `instance_recover`, `mandate_bind`, `mandate_rebind`, `mandate_revoke`, `grant_issue`, `grant_amend`, `grant_revoke`, `grant_renounce`, `acceptance_establish`, `acceptance_amend`, `acceptance_revoke`, `policy_set`, `policy_retire`, `claim_issue`, `contribute`. Its body is a `meta-payload` whose single key is the action name. A body whose key differs from the action name, or that does not decode as `meta-payload`, is malformed (reason `meta-malformed`).

<a id="L0-META-2"></a>**L0-META-2. Payload digest.** The body enters the intent as `intent.opaque.payload = SHA-256("access/meta/v1" ‖ 0x00 ‖ dCBOR(meta-payload))`. A receiver recomputes the digest from the body it is given and never takes it from the input.

<a id="L0-META-3"></a>**L0-META-3. ExerciseID.** `ExerciseID = SHA-256("access/exercise/v1" ‖ 0x00 ‖ dCBOR([DomainID, nonce]))`, where `DomainID` is encoded as a `digest` and `nonce` as a byte string.

<a id="L0-META-4"></a>**L0-META-4. Object identifiers.** The `n`-th object of kind `k` that an Exercise creates has the id `SHA-256("access/object/v1" ‖ 0x00 ‖ dCBOR([origin, k, n]))` truncated to its first 16 bytes. `origin` is the ExerciseID, or the DomainID for objects created by Genesis; both are encoded as a `digest`. `n` counts from 0 within each kind.

## 2. State

<a id="L0-META-5"></a>**L0-META-5. State keys.** The state key of an object is `dCBOR([k, id])`, where `k` is the kind text and `id` its identifier. The kinds are `anchor`, `grant`, `party`, `instance`, `mandate`, `acceptance`, `policy`, `claim` and `contribution`. A Claim is keyed by its ClaimID. A contribution, and an allowed Exercise (`exercise`: its intent digest, actor Instance and position, written by the allowing decision), are keyed `dCBOR([k, ExerciseID])` with the ExerciseID encoded as a `digest`. Five index kinds hold sets of ids: `children` (the Grants whose basis is an Anchor or a Grant, keyed by that id), `instances` (the Instances of a Party, keyed by the Party), `mandates` (the Mandates of an Instance, keyed by the Instance) `acceptances` (the Acceptances whose issuer is a Party, keyed by that Party) and `selection` (the `subject-selection` Acceptances of a class, keyed `dCBOR(["selection", class])`). The index `dCBOR(["key", kid])`, with `kid` the RFC 7638 thumbprint of an Instance's current key, holds that Instance's id; creating, rekeying and recovering an Instance write it, and rekeying and recovering remove the old key's entry.

<a id="L0-META-6"></a>**L0-META-6. Stored status.** A stored object carries its content, the position that created or last changed it (`since`) and, once it has ended, `ended` with the position and the way it ended. Ending is terminal: no meta-action changes an object with `ended` (reason `meta-ended`). Status that depends on time or on other objects, such as expiry or a revoked ancestor, is derived when it is read and never stored.

<a id="L0-META-7"></a>**L0-META-7. Genesis.** The state at position 0 holds the objects that Genesis creates from its `genesis-fields`: the meta-anchor with scope `"domain"` as Anchor 0, then each entry of `anchors`, each Grant of `grants` with its `children` index (a Genesis Grant names its Anchor by position, 0 being the meta-anchor, because the ids derive from the DomainID, which is this record's own digest), and each Acceptance of `acceptances`, with ids by [L0-META-4](#L0-META-4) and `since` 0. A Genesis record with a field that `genesis-fields` does not define is rejected.

## 3. Powers

<a id="L0-META-10"></a>**L0-META-10. Root power.** The actor's Party holds the root of an Anchor when the root is `{sole: P}` with `P` the actor's Party, or `{joint: …}` with the actor's Party among `parties`. A joint root of `k` adds a requirement for `k − 1` contributions of class `co_root`, single use, bound to the intent digest, from distinct Parties. The Anchor's `root_terms` are added as requirements. An Anchor that has ended gives no power.

<a id="L0-META-11"></a>**L0-META-11. Lineage power.** For a Grant `G`, the actor has lineage power when it holds the root of the Anchor at the top of `G`'s lineage, or its Party is the extensional holder of a Grant above `G` in that lineage that has not ended. A lineage longer than 16 is rejected (reason `meta-depth`).

<a id="L0-META-12"></a>**L0-META-12. Own Instance.** A Party has power over its own Instances: those whose `party` is the actor's Party and that have not ended.

<a id="L0-META-13"></a>**L0-META-13. Basis.** The Exercise basis names the power it uses: `{anchor: A}` for root power over `A`, `{holding: …}` for a holding, and `{public: G}` for the self-acting actions `party_register` and `instance_create`. A basis that does not match the meta-action is refused (reason `meta-basis`).

## 4. The meta-actions

<a id="L0-META-20"></a>**L0-META-20. Anchors.** `anchor_create` needs root power over the basis Anchor, and the new scope must lie within that Anchor's scope; a scope of `"domain"` is never created. `anchor_transfer`, `anchor_amend` and `anchor_retire` need root power over the Anchor named, which must also be the basis. The meta-anchor is never retired.

<a id="L0-META-21"></a>**L0-META-21. Dispositions.** `anchor_transfer`, `anchor_retire` and `party_depart` carry a disposition that names exactly the dependent Grants that have not ended, each with `keep` or `revoke`; there is no default (reason `meta-disposition`). `revoke` ends the Grant. `keep` is allowed only on transfer.

<a id="L0-META-22"></a>**L0-META-22. Admission.** `party_register` creates, in one record, the Party's admission and its self-anchor with scope `{party: P}` and the given root. The payload's Party must be the actor's Party, and a Party is registered at most once. `party_depart` needs root power over the meta-anchor; it retires the self-anchor with its disposition and ends the Party and its live Instances.

<a id="L0-META-23"></a>**L0-META-23. Instances.** `instance_create` is for the actor's own Party, which must be admitted; the new Instance's id is the one [L0-META-4](#L0-META-4) gives and must be the actor Instance, so the new key signs its own creation. An optional Mandate is bound in the same record. `instance_rekey` is done by the Instance itself. `instance_terminate` is done by the Instance's Party or with root power over that Party's self-anchor. `instance_recover` is done by the Party; it ends the old Instance and creates exactly one successor that inherits nothing.

<a id="L0-META-24"></a>**L0-META-24. Mandates.** `mandate_bind`, `mandate_rebind` and `mandate_revoke` are done by the Party of the Mandate's Instance. A pin names a holding of that Party that has not ended, with its `since`.

<a id="L0-META-25"></a>**L0-META-25. Grant issue.** With basis `{anchor: A}` the actor needs root power over `A` and the Grant's resource must lie within `A`'s scope. With basis `{holding: [G, P, s]}`, `P` must be the actor's Party and the extensional holder of `G`, `s` must be `G`'s `since`, `G` must not have ended, and the new authority must be within `G`'s by the child-within-parent check of [L0-ALG-70](algebra.md#L0-ALG-70) (reason `meta-not-within`). The Grant's `agency` may hold only `own` and `{for: Q}` where `Q` is the issuing Exercise's principal (reason `meta-agency`).

<a id="L0-META-26"></a>**L0-META-26. Grant changes.** `grant_amend` and `grant_revoke` need lineage power over the Grant. An amend keeps the GrantID, raises `revision` by one and, for a Grant with a holding basis, stays within its parent. `grant_renounce` is done by the extensional holder.

<a id="L0-META-27"></a>**L0-META-27. Domain objects.** `acceptance_*`, `policy_*` and `claim_issue` need root power over the meta-anchor. An amend keeps an Acceptance's `issuer` and `use`. A class has one membership issuer: a `subject-selection` Acceptance is refused when a live one of another issuer names the same class (reason `meta-not-within`). A Claim issued by `claim_issue` has the actor's Party as its issuer and the issuing Exercise's object id as its ClaimID.

<a id="L0-META-30"></a>**L0-META-30. Contributions.** `contribute` is authorized like any domain action: its intent's resource is `access.contribution` with the path `[class]`, and the actor needs a Grant covering it. An anonymous actor never contributes. The payload's `target` is the digest of the intent the contribution is for. An allowed `contribute` writes a `contribution-state` under the key of its ExerciseID with the actor's Party and Instance.

<a id="L0-META-28"></a>**L0-META-28. Expansion.** Each allowed meta-action is either expansion class or not. Creating anything, widening a Grant or a Mandate, changing a root, lowering root terms, retiring a policy and every Acceptance change except revoke are expansion. Revoke, renounce, terminate and narrowing amends are not.

<a id="L0-META-29"></a>**L0-META-29. Effects.** An allowed meta-action writes its state changes as the `effects` of its decision record ([L2-REC-2](../l2/README.md#L2-REC-2)), and the `children`, `instances` and `mandates` indexes with them.

Vectors: [`core/1/meta.json`](../../conformance/vectors/core/1/meta.json), operation `meta.apply`.
