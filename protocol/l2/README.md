# L2 Access-native Parts

Status: first draft, Kernel artefacts only. Not yet adopted.

L2 defines the artefacts that only Access produces: their data model, how they are signed, the media types they travel under and the digest contexts that bind them. The meaning of every field and every verification rule is in [L0](../l0/README.md); L2 adds the parts a producer needs to emit an artefact that any L0 verifier accepts.

## Parts in this version

| Artefact | CDDL rule | Media type | Signed by | Verification rules |
|---|---|---|---|---|
| Domain Metadata | `domain-metadata` | `application/access-domain-metadata+cbor` | A binding key of the domain | [L0-SIG-60](../l0/signatures.md#L0-SIG-60) to [L0-SIG-72](../l0/signatures.md#L0-SIG-72) |
| Operational key excerpt | `key-excerpt` | `application/access-key-excerpt+cbor` | A binding key whose scope covers the domain | [L0-SIG-60](../l0/signatures.md#L0-SIG-60) to [L0-SIG-72](../l0/signatures.md#L0-SIG-72) |
| Record envelope | `record-envelope` | carried inside other artefacts | not signed by itself | [L0-ENC-25](../l0/encoding.md#L0-ENC-25) to [L0-ENC-29d](../l0/encoding.md#L0-ENC-29d) |
| Record disclosure | `record-disclosure` | carried inside other artefacts | not signed by itself | [L0-ENC-29c](../l0/encoding.md#L0-ENC-29c) |
| Decision record fields | `decision-fields` | inside a `decision` record envelope | not signed by itself | [L2-REC-1](#L2-REC-1) to [L2-REC-3](#L2-REC-3) |
| Intent envelope | `intent-envelope` | carried inside other artefacts | not signed by itself | [L0-EVAL-5](../l0/evaluation.md#L0-EVAL-5) |
| Actor Intent Statement | `actor-intent-statement` | `application/access-ais+cbor` | The actor Instance's current key | [L2-AIS-1](#L2-AIS-1) to [L2-AIS-4](#L2-AIS-4) |
| Opening record fields | `opening-fields` | inside an `opening` record envelope | not signed by itself | [L2-REC-4](#L2-REC-4), [L2-REC-5](#L2-REC-5) |
| Claim | `claim-statement` | `application/access-claim+cbor` | An Instance of the issuer | [L2-CLM-1](#L2-CLM-1) to [L2-CLM-3](#L2-CLM-3) |
| Claim record fields | `claim-fields` | inside a `claim` record envelope | not signed by itself | [L2-CLM-4](#L2-CLM-4) |
| Decision receipt | `receipt` | `application/access-receipt+cbor` | An operational key of the domain with usage `receipt` | [L2-RCP-1](#L2-RCP-1) to [L2-RCP-3](#L2-RCP-3) |
| Portable Authority Proof | `pap` | `application/access-pap+cbor` | An operational key of the domain with usage `pap` | [L2-PAP-1](#L2-PAP-1) to [L2-PAP-3](#L2-PAP-3) |
| PAP presentation | `pap-presentation` | `application/access-pap-presentation+cbor` | The holder's key | [L2-PAP-3](#L2-PAP-3) |
| Claim body | `claim-body-binding` | travels beside its Claim | not signed by itself; its digest is the Claim's `value` | [L2-CLB-1](#L2-CLB-1) to [L2-CLB-3](#L2-CLB-3) |
| Unsigned Claim | `unsigned-claim` | carried over an authenticated channel | not signed | [L2-CLM-5](#L2-CLM-5) |
| Approval Act Statement | `approval-act-statement` | `application/access-aas+cbor` | The approver Instance's key, or a WebAuthn assertion over its digest | [L2-AAS-1](#L2-AAS-1) to [L2-AAS-4](#L2-AAS-4) |
| Offline Exercise Report | `offline-exercise-report` | the body of an `offline_exercise_report` Claim | the verifier, as the Claim's issuer | [L2-RPT-1](#L2-RPT-1) to [L2-RPT-3](#L2-RPT-3) |
| Verifier Profile | `verifier-profile` | the body of a `verifier_profile` Claim | the verifier's operator, as the Claim's issuer | [L2-VPR-1](#L2-VPR-1) |
| Access token | RFC 9068 JWT with RFC 9396 `authorization_details` | `at+jwt` | An operational key of the domain with usage `token` | [L2-JOS-1](#L2-JOS-1) to [L2-JOS-4](#L2-JOS-4) |
| PAP in SD-JWT | the fields of `pap` in an SD-JWT | `access-pap+sd-jwt` | An operational key of the domain with usage `pap` | [L2-JOS-5](#L2-JOS-5), [L2-JOS-6](#L2-JOS-6) |
| Token Status List | `status-list-cwt`, `status-ref` | `application/statuslist+cwt`, `application/statuslist+jwt` | An operational key of the domain with usage `status-list` | [L2-STL-1](#L2-STL-1) to [L2-STL-3](#L2-STL-3) |

The data model is [`conformance/cddl/kernel.cddl`](../../conformance/cddl/kernel.cddl).

## Decision record fields

<a id="L2-REC-1"></a><!-- no-vector: definition: the field set; its use is checked by L2-REC-2 and L2-REC-3 -->**L2-REC-1.** A record of kind `decision` carries the fields of the CDDL rule `decision-fields`, each with its own commitment ([L0-ENC-28](../l0/encoding.md#L0-ENC-28)):

| Field | Meaning |
|---|---|
| `outcome` | The Kernel decision ([L0-EVAL-1](../l0/evaluation.md#L0-EVAL-1)) |
| `state_basis` | The position the evaluation read the state at, and every state key it read with the version it saw |
| `consumption` | Counter draws and single-use flags the decision consumes |
| `effects` | The state changes the decision makes: `[key, value]` sets a key, `[key]` removes it |
| `versions` | The specification versions the decision was made under |
| `nonce`, `intent` | The request nonce and the intent digest ([L0-ENC-23](../l0/encoding.md#L0-ENC-23)) |
| `proof_commit` | Digests of the signed bytes the decision cites |
| `artifacts` | Digests of the artefacts issued for the decision |
| `validity` | The ValidityContract, only when the result is reusable |

A disclosure for an artefact opens `artifacts` and withholds `state_basis` and `consumption`.

<a id="L2-REC-2"></a>**L2-REC-2.** Only a `decision` record whose outcome is `allow`, and a `claim` record whose disposition is `admit`, carry `effects`; a `claim` record's effects touch only `claim`, `member` and `successor` keys. Any other record that carries `effects` is malformed. Within one record a key appears in at most one effect. A key is 1 to 512 bytes.

<a id="L2-REC-3"></a>**L2-REC-3. State fold.** The state of a domain at position `p` is the fold of the `effects` of records `1..p` in position order: a key's value is the value of the last effect for it, and its version is that record's position. An effect without a value leaves the key absent with that version. No other input changes the state; a replica, index or cache that disagrees with the fold is wrong.

Vectors: [`core/1/record-fold.json`](../../conformance/vectors/core/1/record-fold.json), operation `record.fold`: each case gives the records in position order as canonical envelopes and the resulting state as `[key, value, version]` triples sorted by key bytes (`value` is `null` in the JSON for an absent key), or the rejection.

## Actor Intent Statement

The Actor Intent Statement (AIS) is how an actor makes an Exercise its own. A PEP forwards it and cannot produce it. Without one, the actor is anonymous and holds only what `Public` holds.

<a id="L2-AIS-1"></a>**L2-AIS-1. Content.** An AIS is a COSE_Sign1 with content type `application/access-ais+cbor` whose payload is an `actor-intent-statement`: the DomainID, the nonce (16 to 64 bytes), the intent digest ([L0-ENC-23](../l0/encoding.md#L0-ENC-23)), the mode, the PEP's identity as the actor addressed it, the capacity, the basis, the signing time `iat` and, for `continue`, the ExerciseID. A payload of another shape is rejected (reason `ais-payload`).

<a id="L2-AIS-2"></a>**L2-AIS-2. Key.** The AIS verifies under the actor Instance's current key, with `kid` its RFC 7638 thumbprint, under the profile of [L0-SIG-10](../l0/signatures.md#L0-SIG-10). An Access actor is a native signer: a high-S ECDSA signature is rejected. Any other key, including a key the Instance has rotated away from, is rejected (reason `ais-signature`).

<a id="L2-AIS-3"></a>**L2-AIS-3. Binding.** Every signed field equals the request: the domain addressed, the nonce, the intent digest the receiver computes itself, the mode, the PEP's transport-authenticated identity, the capacity, the basis and, for `continue`, the ExerciseID. A difference is a protocol error, not a decision, and names the first differing field in that order (reason `ais-mismatch`).

<a id="L2-AIS-4"></a>**L2-AIS-4. Time.** An AIS whose `iat` is more than 60 seconds after the receiver's trusted time is rejected (reason `ais-future`). How old an AIS may be is decided by the nonce rule of [L2-REC-5](#L2-REC-5).

Vectors: [`core/1/ais.json`](../../conformance/vectors/core/1/ais.json), operation `ais.verify`: each case gives the COSE_Sign1, the request as an `actor-intent-statement` whose `iat` is ignored, and the trusted time; the file gives the Instance's key, and a case that gives its own `key` uses that one. The `esp256-` cases are a P-256 Instance.

## Claims

A Claim is a signed statement by an issuer Party about a subject Party. It enters a decision only as a proof, and only when an Acceptance of the domain admits it; ingest alone never makes it count.

<a id="L2-CLM-1"></a>**L2-CLM-1. Content.** A Claim is a COSE_Sign1 with content type `application/access-claim+cbor` whose payload is a `claim-statement`. Its ClaimID is the first 16 bytes of `SHA-256("access/claim/v1" ‖ 0x00 ‖ the COSE_Sign1 bytes as received)`. A payload of another shape, or a Claim for another domain, is rejected (reason `claim-payload`).

<a id="L2-CLM-2"></a>**L2-CLM-2. Key.** The Claim verifies under the current key of an Instance of its issuer, with `kid` the key's RFC 7638 thumbprint, under the profile of [L0-SIG-10](../l0/signatures.md#L0-SIG-10); a high-S ECDSA signature is rejected. Any other key is rejected (reason `claim-signature`). A rejected Claim is a protocol error and is not recorded.

<a id="L2-CLM-3"></a>**L2-CLM-3. Disposition.** A verified Claim whose `issued_at` is more than 60 seconds after trusted time is `quarantine:future`. Otherwise it is `admit` when an Acceptance that has not ended covers it at the record's time: use `predicate-input` or `subject-selection`, the same issuer, its class among `classes`, its subject within `subject` (a Party or `Public`), the record time within `validity` and not after `ingest_until`, `issued_at` not after `issued_until`, and its assurance meeting `assurance_floor`; else it is `quarantine:source-not-accepted`. An admitted Claim draws one from its issuer's quota for the window: the most generous `quota` of the Acceptances that admit it (1000 per 3600 s when one declares none), with a limit of twice the count; when the limit is reached it is `quarantine:quota` instead. A recorded Claim is a proof only while a `predicate-input` Acceptance covers it, and a group membership only while a `subject-selection` Acceptance covers it. Neither holds for a Claim that is not current: one with a recorded successor of the same issuer, subject and class, or one whose `supersedes` names a Claim with two or more such successors (TI-RT7).

<a id="L2-CLM-4"></a>**L2-CLM-4. Claim record.** Each Claim carried by a request is written as a record of kind `claim` with the fields of `claim-fields`, before the opening and decision records of the same batch, and its bytes go to the proof store. An admitted Claim's record sets its `claim-state` and the membership entry `dCBOR(["member", class, subject, ClaimID])` holding the ClaimID, and, when the Claim names `supersedes: S`, the entry `dCBOR(["successor", S, ClaimID])` holding the ClaimID. An admitted ClaimID is not written again; a Claim held in quarantine may be sent again and gets a new record with a new disposition.

## Exercise records

<a id="L2-REC-4"></a><!-- no-vector: definition: the field set of the opening record; its use is in L2-REC-5 -->**L2-REC-4. Opening record.** Each evaluation in `commit` or `continue` writes a record of kind `opening` with the fields of `opening-fields` (nonce, actor Instance or `"anonymous"`, basis, capacity, intent digest, AIS digest, proof commitments and, for `continue`, the ExerciseID), followed in the same batch by its `decision` record. A re-evaluation of an open nonce writes only a new `decision` record.

<a id="L2-REC-5"></a><!-- no-vector: outside-operation: the nonce table is the commit path's, not an evaluator operation -->**L2-REC-5. Nonce.** A nonce belongs to one intent digest and one actor in its domain. Its outcomes form an append-only sequence: `allow` and `deny` are terminal and nothing follows them; `require_action` leaves it open until the intent's validity ends. The same nonce, intent and actor after a terminal outcome returns that outcome's records again. The same nonce with another intent or actor is a protocol error. An AIS whose nonce is new is accepted only while its age is within the intent validity ceiling.

## Decision receipts

<a id="L2-RCP-1"></a><!-- no-vector: definition: the field set; L2-RCP-3 checks it -->**L2-RCP-1.** A receipt carries the fields of the CDDL rule `receipt`: the domain, the ExerciseID and the position of its decision record, the intent digest, the actor Instance and the digest of its AIS (both absent for an anonymous actor), the capacity, the basis, the audience (the PEP that applies the decision), `iat` (the trusted evaluation time, which is also the signing time), `drawn` (whether the ALLOW drew from a budget) and, when the actor acted on behalf of others, `agency`: the chain of `{mandate, principal, agent}` links in order from the principal to the agent, where each link's agent is the next link's principal. A receipt with an empty `agency` is malformed. A receipt names one Exercise, one intent and one audience; it is never a credential for another effect.

<a id="L2-RCP-2"></a><!-- no-vector: outside-operation: a producer rule; the core test an_allow_carries_a_signed_receipt checks it -->**L2-RCP-2.** The producer computes the receipt digest under the context `access/receipt/v1` and writes it into the decision record's `artifacts` before the commit. It signs the receipt only after the record is committed, with an operational key whose excerpt names usage `receipt` and whose window contains `iat` ([L2-SIG-3](#L2-SIG-3)). If no key may sign, the receipt is delayed; an unsigned receipt is never released. Under a domain whose `hybrid` policy is `both` or `pq`, the producer signs the same payload with the ML-DSA operational key too and sends the CDDL `hybrid-artefact` carrier `[classic, pq]` in place of the single COSE_Sign1, with the ML-DSA component's excerpt beside the classical one (`pq_excerpt` in the ADP answer, `pq_key_excerpt` in the kept Exercise); a PAP travels the same way. Under `both` a verifier accepts only both components over the same payload; one alone is `hybrid-missing` ([L0-SIG-75a](../l0/signatures.md#L0-SIG-75a)).

<a id="L2-RCP-3"></a>**L2-RCP-3.** A verifier accepts a receipt only when all of these hold, checked in this order: the payload decodes as `receipt`; the excerpt resolves an operational key of the receipt's domain for usage `receipt` at its `iat` ([L0-SIG-60](../l0/signatures.md#L0-SIG-60) to [L0-SIG-72](../l0/signatures.md#L0-SIG-72)); the COSE_Sign1 verifies under that key; the domain is the verifier's domain; the audience is the verifier itself; the intent digest is the intent it is about to apply; and `iat` is no later than the verifier's time plus the AIS skew. When the excerpt is signed by a superseded binding key, the verifier MAY pass the receipt's inclusion evidence ([L0-SIG-64](../l0/signatures.md#L0-SIG-64), [L0-SIG-80](../l0/signatures.md#L0-SIG-80)): the evidence MUST name the receipt's own digest (`access/receipt/v1` over the payload), which the decision record commits as a member of `artifacts`; evidence naming any other artefact refuses the key with `receipt-key`, and evidence never replaces the signature check. Rejection reasons: `receipt-malformed`, `receipt-key`, `receipt-signature`, `receipt-domain`, `receipt-audience`, `receipt-intent`, `receipt-future`.

Vectors: [`core/1/receipt.json`](../../conformance/vectors/core/1/receipt.json), operation `receipt.verify`; [`core/1/receipt-evidence.json`](../../conformance/vectors/core/1/receipt-evidence.json), operation `receipt.verify_with_evidence`.

## Portable Authority Proofs

<a id="L2-PAP-1"></a><!-- no-vector: definition: the field set; L2-PAP-3 checks it -->**L2-PAP-1.** A PAP carries the fields of the CDDL rule `pap`: the domain, the ExerciseID of the `projection.issue` that produced it, the holder (Instance and its public key), the capacity, the bounds (an authority set within the holder's exercisable authority, catalog prefixes pinned), the requirements a verifier must check locally, the ValidityContract, the digest of the basis lineage and `iat`. The contract's `holder` is the digest of the `holder` value under `access/holder/v1`; its `audience`, `offline_slice` and `must_understand` are the PAP's. An action whose requirements a verifier cannot check locally is not in the bounds.

<a id="L2-PAP-2"></a><!-- no-vector: outside-operation: a producer rule checked by the core tests of projection.issue -->**L2-PAP-2.** The producer records the PAP's digest (`access/pap/v1` over the PAP payload) in the `projection.issue` decision record's `artifacts` before the commit and signs only after it, with an operational key whose excerpt names usage `pap` and whose window contains `iat`. A presentation's `pap` digest is taken over the signed COSE_Sign1 bytes under the same context.

<a id="L2-PAP-3"></a>**L2-PAP-3.** A verifier accepts the use of a PAP for an intent only when all of these hold, in this order: (1) the payload decodes as `pap`; the excerpt resolves an operational key of the PAP's domain for usage `pap` at its `iat`; the COSE_Sign1 verifies under it; the domain is the verifier's (`pap-malformed`, `pap-key`, `pap-signature`, `pap-domain`); (2) the contract allows use now for this verifier ([L0-VAL](../l0/validity.md)) and its `holder` is the digest of the PAP's holder (`pap-validity`, `pap-holder`); (3) the presentation decodes, verifies under the holder key, names this PAP's digest, the intent, the verifier as audience and the verifier's nonce, and its `iat` is within the AIS skew of the verifier's time (`pap-presentation`); (4) the intent is within the bounds and every local requirement is one the verifier reports satisfied (`pap-bounds`, `pap-requirements`); (5) the intent's demand fits what remains of the offline slice the verifier keeps (`pap-slice`); (6) the verifier's Domain Metadata is fresh (`pap-stale`). Must-understand items are part of step 2.

Vectors: [`core/1/pap.json`](../../conformance/vectors/core/1/pap.json), operation `pap.verify`.

## Claim bodies

The Claims that cross from the identity plane, from verifiers and from PEPs have classes with structure. A class with one scalar field carries it in the Claim's `value`; any other class carries a body, and the Claim's `value` is the body's digest. The body travels beside the Claim and can be withheld, which leaves a Claim whose value is only a digest.

<a id="L2-CLB-1"></a>**L2-CLB-1. Body digest.** A Claim of a class with a body carries in `value` the 32 bytes of `SHA-256("access/claim-body/v1" ‖ 0x00 ‖ dCBOR([class, body]))`, the CDDL rule `claim-body-binding`. The class is inside the digest, so a body of one class never stands for another. Class names on the wire are idents: `account.status` is `account_status`, `party.key-state` is `party_key_state`, `identity-binding.person` is `identity_binding_person`.

<a id="L2-CLB-2"></a>**L2-CLB-2. Values.** The classes `account_status` (one of `active`, `locked`, `suspended`, `deactivated`, `tombstone`), `party_compromise` (`occurred_at`, a non-negative integer, or absent), `party_terminated` (a non-negative integer), `party_identity_break` and `agent_kind` (an ident), `controller_of`, `operated_by`, `sponsored_by` and `org_member` (a PartyID; for `org_member` the organization whose member the subject is), and `attestation_runtime` (32 bytes, the digest of the attested runtime class) carry their field in `value` and travel without a body. Every other class in the table of `kernel.cddl` carries a 32-byte digest in `value`. A value of another shape is refused (reason `claim-value`). A Claim of a class with a body that arrives without it is accepted as a digest-valued Claim: what is withheld cannot be read by a policy, so it can only fail a requirement that needs it. Classes outside the table are not checked by this rule.

<a id="L2-CLB-3"></a>**L2-CLB-3. Bodies.** A body that arrives beside its Claim is decoded as the CDDL body of the Claim's class (`authentication`, `authenticator-binding`, `device-posture`, `verifier-profile`, `offline-exercise-report`, `authority-state-ack`, `party-key-state`, `party-recovered`, `identity-binding`, `effect-attestation`, `executor-control`); a field the rule does not define, or any other shape, is refused (reason `claim-body`). Only an `identity_binding_workload` body carries `workload`; an `effect_attestation` whose `outcome` is `done` names at least one evidence kind (E64 (2)). Its digest under [L2-CLB-1](#L2-CLB-1) must be the Claim's value (reason `claim-body-digest`). An `authenticator-binding` body holds only the digest of public material; a secret has no field to go in.

Vectors: [`core/1/claim-body.json`](../../conformance/vectors/core/1/claim-body.json), operation `claim.body`: each case gives the class, the canonical `value` when there is one and the body when it travels, and the result: the digest the body was checked against, `valid` when nothing more was checked, or the reason.

<a id="L2-CLM-5"></a>**L2-CLM-5. Unsigned Claims.** A Claim may arrive without a signature over an authenticated channel, as the CDDL rule `unsigned-claim`: the statement and the channel it came over, a PEP (`pep`, the SHA-256 thumbprint of its client certificate) or a SCIM client (`scim`). It is read only when the statement is for the receiver's domain and the channel it names is the one it arrived on (reason `claim-payload` otherwise). Its ClaimID is taken over the bytes as received, as in [L2-CLM-1](#L2-CLM-1). An unsigned Claim is attributable to its channel but never meets an assurance floor that asks for a signature. A PEP fact is an unsigned Claim from a PEP: only a `predicate-input` Acceptance admits it, and it never selects a holder.

Vectors: [`core/1/claim-unsigned.json`](../../conformance/vectors/core/1/claim-unsigned.json), operation `claim.unsigned`: each case gives the bytes, the channel the receiver saw and the resulting ClaimID or the reason.

## Approval Act Statements

An approval is one act by one person, bound to one statement of what they approved. The statement is never an intent: its `target` is the digest of the intent it approves.

<a id="L2-AAS-1"></a>**L2-AAS-1. Content and digest.** An Approval Act Statement is the CDDL rule `approval-act-statement`. An act of kind `contribution` names its `contribution_class`; an `authority-act` names none. Its `surface` may declare the surface's `class` (`voice`, `watch`, `phone`, `desktop`) and the `evidence` the act reached (`presence`, `user_verified`, `phishing_resistant`); the decision point gives the approval's proof the `surface` level of the class (voice 0, watch 1, phone or desktop 2), `human_presence` 1, and `uv` and `phishing_resistant` as far as the evidence reaches, and claims nothing for what is undeclared (E49). H(AAS) is the digest of the statement under `access/aas/v1`. A WebAuthn assertion carries the 32 bytes of H(AAS) as its challenge; an `authentication` Claim made from either form names H(AAS) in its `statement`.

<a id="L2-AAS-2"></a>**L2-AAS-2. Signed form.** An Instance key may sign the statement as a COSE_Sign1 with content type `application/access-aas+cbor`, under the approver Instance's current key with `kid` its RFC 7638 thumbprint and the profile of [L0-SIG-10](../l0/signatures.md#L0-SIG-10). Any other key or content type is refused (reason `aas-signature`); a payload that is not a statement is refused (reason `aas-malformed`).

<a id="L2-AAS-3"></a>**L2-AAS-3. Binding.** The decision point accepts a statement only for its own domain (`exercise_ref`), for the intent digest it is deciding (`target`), from the approver Instance the assertion authenticated and with the render digest it computed itself from the accepted action schema, checked in this order (reasons `aas-domain`, `aas-target`, `aas-approver`, `aas-render`).

<a id="L2-AAS-4"></a>**L2-AAS-4. Time.** A statement whose `issued_at` is more than the AIS skew (60 seconds) after trusted time is refused (reason `aas-future`). One whose `expires_at` is before its `issued_at`, or before trusted time, is refused (reason `aas-expired`); `expires_at` itself is still inside.

Vectors: [`core/1/aas.json`](../../conformance/vectors/core/1/aas.json), operation `aas.verify`: the file gives the approver's key and the expected domain, target, Instance and render digest; each case gives the COSE_Sign1 and the trusted time, and the resulting H(AAS) or the reason.

## Offline Exercise Reports

An offline verifier reports its local uses when it reconnects. The report is a Claim: it never changes authority state or what remains of a budget, and only an explicit `consumption_release` can return an unused slice.

<a id="L2-RPT-1"></a>**L2-RPT-1. Content.** A report is the body of an `offline_exercise_report` Claim, the CDDL rule `offline-exercise-report`: the verifier's profile digest and Instance, the projection's ExerciseID and contract digest (the `validity-contract` under `access/validity/v1`), the local period it covers, the chain start (`previous`, `first_seq`), the entries, the chain head, the unused slice and the profile version. Each entry gives the intent digest, the parameter digest, the local time and clock evidence, the local outcome, what it drew from the slice and the holder's proof (the digest of the holder's presentation COSE_Sign1 as received, under `access/pap-presentation/v1`). A body of another shape is refused (reason `report-malformed`).

<a id="L2-RPT-2"></a>**L2-RPT-2. Chain.** The chain of a projection starts at the digest of `[exercise, contract]` under `access/report-chain/v1`. The entry numbered `seq` moves it from `h` to the digest of `[h, seq, entry]` under the same context. A projection's first report has `first_seq` 0 and no `previous`; each later report names the head the previous one ended with and starts at the next number. A report that does not continue the last head leaves a gap that reconciliation shows; it does not reset the chain.

<a id="L2-RPT-3"></a>**L2-RPT-3. Checks.** A report is accepted only when `previous` is present exactly when `first_seq` is not 0 (`report-start`), every entry's time lies in the period (`report-period`), only `allow` entries draw and no total overflows (`report-entry`), and the chain through every entry from `previous`, or from the projection's start, leads to `head` (`report-chain`). An accepted report gives its head, the next sequence number and the total drawn per budget term.

Vectors: [`core/1/report.json`](../../conformance/vectors/core/1/report.json), operation `report.verify`.

## Verifier Profiles

<a id="L2-VPR-1"></a><!-- no-vector: no-operation: issuing a contract is a projection.issue decision; the Kernel's covers and cap_horizon are property-tested -->**L2-VPR-1. Profile.** A verifier declares its capabilities as the body of a `verifier_profile` Claim, the CDDL rule `verifier-profile`: who it is, the connectivity variants it implements with their parameter ceilings, the versions it supports, its clock, whether it keeps a tamper-evident counter, sends offline reports and checks content positions, the status sources it reaches, its refresh interval, its attestation, its local horizon ceilings by variant and CT (`cap_horizon`) and slice ceilings, and its conformance declarations. A contract's `verifier_profile_ref` is the body digest of the profile it was issued against. A profile covers a contract only when it implements the contract's variant and declares a ceiling at or above each of the contract's parameters; an issuer does not issue a contract the profile does not cover.

## Token Status List

A projection may have one entry in a domain's Token Status List. The list is an information channel: a verifier that cannot read a fresh list falls back to the contract's horizon and Δ and does not accept beyond them.

<a id="L2-STL-1"></a>**L2-STL-1. Reference.** A ValidityContract's `status` is the CDDL rule `status-ref`, the `status` claim of the IETF Token Status List: the projection's index `idx` in the list at `uri`.

<a id="L2-STL-2"></a>**L2-STL-2. List token.** A list token is a COSE_Sign1 with content type `application/statuslist+cwt` whose payload is `status-list-cwt`, signed by an operational key with usage `status-list`; the JWT form `application/statuslist+jwt` carries the same claims. Each entry is one bit (`bits` 1). `iat` and `as_of` are the `recorded_at` and the position of the canonical state the list reflects, never the publication time, so a late list uses up Δ instead of extending it. A payload of another shape is refused (reason `status-malformed`).

<a id="L2-STL-3"></a>**L2-STL-3. Lookup.** The entry is read only from the list the reference names (`status-uri`). After ZLIB decompression of `lst`, index `i` is bit `i mod 8` of byte `i div 8`, least significant bit first; an index past the end is refused (`status-index`). A set bit is invalid.

Vectors: [`core/1/status-list.json`](../../conformance/vectors/core/1/status-list.json), operation `status.lookup`: each case gives the token payload, the decompressed list and the reference, and whether the entry is invalid or the reason.

## JOSE containers

An access token and the web form of a PAP carry Access content in a JOSE container. The container is signed by an operational key of the domain, with the key's own algorithm (Ed25519 by default, ES256 in the FIPS profile), and verifies under the JWS and SD-JWT profiles of L0 ([L0-SIG-30](../l0/signatures.md#L0-SIG-30) to [L0-SIG-53](../l0/signatures.md#L0-SIG-53)). The key set a verifier uses holds the domain's operational keys for the usage (`token` for an access token, `pap` for a PAP) whose windows contain the artefact's `iat` ([L0-SIG-60](../l0/signatures.md#L0-SIG-60) to [L0-SIG-72](../l0/signatures.md#L0-SIG-72)); digests in JOSE JSON are in the text form `sha-256:<base64url>` ([L0-ENC-20](../l0/encoding.md#L0-ENC-20)). Each check below fails with one reason; the checks run in the order given and the first failure decides.

<a id="L2-JOS-1"></a>**L2-JOS-1. Access token.** An access token projection is an RFC 9068 JWT with `typ` `at+jwt`, verified as a native JWS. It carries `iss` (the AS issuer), exactly one string `aud` (the resource server, which must be in the contract's audience), `sub` (the principal's domain-pairwise reference), `exp` (the horizon), `iat`, `jti` (the `projection.issue` ExerciseID), `client_id`, `cnf` and `authorization_details`. Its authority is only in `authorization_details` (RFC 9396): each entry names its `type` as `<namespace>:<name>:<major>`, its `kind`, the `domain` in text form and its `validity`. An entry of kind `intent` is an exact-intent token and is the only entry; entries of kind `bounds` are a bounds token, one per fully named action. The verifier returns the kind.

<a id="L2-JOS-2"></a>**L2-JOS-2. Token checks.** The JWS verifies under the key set with `typ` `at+jwt` (`projection-jws`); the payload is a strict I-JSON object (`projection-json`, or `projection-member` for a value that is not an object); `aud` is one string and `iss`, `aud`, `exp`, `nbf` and `iat` pass [L0-SIG-41](../l0/signatures.md#L0-SIG-41) to [L0-SIG-41b](../l0/signatures.md#L0-SIG-41b) for the expected issuer and this resource server (`projection-claims`); `iat` is an integer and `sub`, `jti` and `client_id` are non-empty strings (`projection-member`).

<a id="L2-JOS-3"></a>**L2-JOS-3. Confirmation.** A bearer token does not exist. `cnf` is an object (`projection-member` otherwise) with exactly one member, `jkt` (RFC 9449) or `x5t#S256` (RFC 8705), whose value is the base64url SHA-256 thumbprint of the key or certificate the request was made with; any other member, a second member, another method or another thumbprint is refused (`projection-confirmation`).

<a id="L2-JOS-4"></a>**L2-JOS-4. Authority.** `authorization_details` is an array (`projection-member` otherwise) of one or more objects. Each object has a non-empty string `type` and `kind` (`projection-member`); a `kind` other than `intent` or `bounds`, entries of both kinds, more than one `intent` entry, an empty array or an entry that is not an object are refused (`projection-authority`); `domain` is a string (`projection-member`) equal to the verifier's DomainID in text form (`projection-domain`, TI-RT6); `validity` is an object (`projection-member`).

Vectors: [`core/1/access-token.json`](../../conformance/vectors/core/1/access-token.json), operation `projection.access_token`: the file gives the key set and the context (issuer, audience, domain in text form, `now`, `skew_ms`); each case gives the token and the presented confirmation (`{member: thumbprint}`), and the kind or the reason.

<a id="L2-JOS-5"></a>**L2-JOS-5. PAP in SD-JWT.** A PAP for web and cross-domain use is an SD-JWT ([L0-SIG-50](../l0/signatures.md#L0-SIG-50)) whose issuer-signed JWT has `typ` `access-pap+sd-jwt`. It carries `iss` (the DomainID in text form), `iat` and `exp` in seconds rounded down (`exp` is the horizon), `cnf.jwk` (the holder key), `_sd_alg` `sha-256` and the fields of [L2-PAP-1](#L2-PAP-1) under their CDDL names; `holder` names only the Instance, and there is no `aud`: the audience is in the contract and the verifier binds itself through the Key Binding JWT's `aud` and `nonce`. No field is selectively disclosable in this version. The presentation verifies under [L0-SIG-50](../l0/signatures.md#L0-SIG-50) to [L0-SIG-53](../l0/signatures.md#L0-SIG-53) with that `typ`, the verifier as audience and its nonce (`projection-sd-jwt`), and must be holder-bound: a presentation without a Key Binding JWT is refused (`projection-holder`).

<a id="L2-JOS-6"></a>**L2-JOS-6. PAP members.** `iss` is a non-empty string (`projection-member`) equal to the verifier's DomainID in text form (`projection-domain`); `iat` is an integer; `projection_exercise` and `lineage_commitment` are non-empty strings; `holder`, `bounds` and `validity` are objects; `capacity` is present (`projection-member`). The rest of [L2-PAP-3](#L2-PAP-3) (validity, bounds, local requirements, slice and freshness) applies to the decoded members as it does to the COSE form.

Vectors: [`core/1/pap-sd-jwt.json`](../../conformance/vectors/core/1/pap-sd-jwt.json), operation `projection.pap_sd_jwt`: the file gives the key set and the context (audience, nonce, domain in text form, `now`, `skew_ms`); each case gives the presentation and `valid` or the reason.

## Signing profile

<a id="L2-SIG-1"></a>**L2-SIG-1.** Every L2 artefact is a COSE_Sign1 whose protected header carries exactly `alg`, the content type and `kid`, as [L0-SIG-10](../l0/signatures.md#L0-SIG-10) requires. The payload is the deterministic CBOR encoding of the artefact.

<a id="L2-SIG-2"></a>**L2-SIG-2.** The default algorithm is Ed25519 (COSE `-19`). ESP256 (`-9`) is also produced on request. A producer never signs an L2 artefact with RSA or with a realm JOSE key.

<a id="L2-SIG-3"></a>**L2-SIG-3.** A producer only signs with an operational key inside its excerpt window, and only for usages the excerpt names.

## Digest contexts

<a id="L2-DIG-1"></a>**L2-DIG-1.** Every digest an L2 artefact carries is computed by the producer from canonical CBOR under a context string from the table in [L0-ENC-22](../l0/encoding.md#L0-ENC-22). A verifier recomputes it and never takes a digest from the input.

## Checkpoints

A checkpoint is the signed tree head of a log. Access uses the C2SP formats as published in their v1.1.0 family: [`signed-note`](https://c2sp.org/signed-note), [`tlog-checkpoint`](https://c2sp.org/tlog-checkpoint) and [`tlog-cosignature`](https://c2sp.org/tlog-cosignature). The rules below restate the parts a verifier needs; where they differ from C2SP, C2SP wins.

<a id="L2-CKP-1"></a>**L2-CKP-1. Checkpoint body.** The body has at least three lines, each ending in a newline: the log origin; the tree size as ASCII decimal without leading zeros (`0` for an empty tree); the RFC 9162 root hash in standard base64 with padding. Any further lines are extension lines and are non-empty. The origin is non-empty UTF-8 of at most 255 bytes without whitespace, `+` or control characters. A body that breaks these rules is rejected (reason `checkpoint-malformed`).

<a id="L2-CKP-2"></a>**L2-CKP-2. Note syntax.** A note is the body, one empty line, then one or more signature lines `— <name> <base64>` (the dash is U+2014), each ending in a newline. The body is UTF-8 without control characters other than newline (reason `note-control`). Base64 is standard with padding and only its canonical spelling is accepted. The decoded signature starts with a four-byte big-endian key ID. Two lines with the same name and key ID are rejected (reason `note-duplicate`). A verifier accepts at least 16 and at most 64 signature lines. Anything else is `note-malformed`.

<a id="L2-CKP-3"></a>**L2-CKP-3. Known keys.** A verifier knows each key by name, key ID and public key. The key ID of an Ed25519 key is the first four bytes of `SHA-256(name ‖ 0x0A ‖ type ‖ key)`, with type `0x01` for a log key and `0x04` for a cosigner. Signature lines from unknown keys are ignored. A line from a known key that does not verify rejects the note. A checkpoint is accepted only when the log's own Ed25519 signature over the body verifies (reason `note-unverified` otherwise) and the origin is the one the verifier expects.

<a id="L2-CKP-4"></a>**L2-CKP-4. Cosignatures.** A witness cosignature is `timestamp ‖ signature`: an eight-byte big-endian POSIX timestamp in seconds, then an Ed25519 signature over the lines `cosignature/v1`, `time <timestamp>` and the whole checkpoint body, extension lines included. The timestamp a verifier reports is the one that was signed.

<a id="L2-CKP-5"></a><!-- no-vector: outside-operation: a producer and Reference Verifier rule; the sequencer test a_checkpoint_of_the_committed_head_verifies and the verifier test metadata_freshness_comes_from_a_witness check it -->**L2-CKP-5. Access domain checkpoint lines.** A domain checkpoint carries four extension lines in this order: `recorded_at <ms>` of the head record, `versions sha-256:<base64url>` of the adopted `SpecVersions`, `metadata sha-256:<base64url>` of the binding-signed Domain Metadata current at the head (SHA-256 under the context `access/domain-metadata/v1` over the signed bytes), and `issued_at <ms>`. A checkpoint written before the `metadata` line existed has the other three and names no metadata. A verifier takes a witness cosignature as the freshness of its Domain Metadata only from a checkpoint whose `metadata` line names the digest of the metadata it holds; any other checkpoint refreshes nothing (reason `other-metadata`), and the verifier fetches the metadata it names first (OP-152 m.5 (h)).

Vectors: [`exchange/1/checkpoint.json`](../../conformance/vectors/exchange/1/checkpoint.json), operation `note.checkpoint`: each case gives a note and either the checkpoint it carries (size, root, number of extension lines, cosignature timestamps) or the rejection reason.

## Carrier budgets

<a id="L2-BUD-1"></a>**L2-BUD-1. Carrier budgets.** An artefact travels in a carrier only within its budget: an HTTP header (such as `Authorization` or `DPoP`) and an NFC record hold at most 8192 bytes, a cookie at most 4096 bytes and only an opaque session id, and one QR code (version 40-L, byte mode) at most 2953 bytes. A producer does not emit an artefact over its carrier's budget. An offline PAP travels in the smallest offline carrier that holds it, a QR code or else an NFC record, and never by reference; one that neither holds is refused (reason `projection-over-budget`). Any other PAP whose base64url text is over the header budget is answered by a `projection_ref` instead.

Vectors: [`exchange/1/pq-budgets.json`](../../conformance/vectors/exchange/1/pq-budgets.json), operation `budget.fits`: each case gives a carrier and a size and whether the size fits.

## Later parts

These parts arrive with the features that produce them, each in its own version of this track:

| Part | Contents |
|---|---|
| Actor Intent Statement (AIS) | The signed statement of an actor's exact intent |
| Schema Publication Package | Action schemas and their catalog digests |
| Authority Record Exchange | Record transfer, handover and recovery |

## License

[Apache License 2.0](../../LICENSE).
