# L0 Core Semantics

Status: first draft, core track version 1. Not yet adopted.

L0 is the part of the Access Protocol that every implementation must agree on bit for bit. It defines how values are encoded and hashed, how authority is compared and narrowed, how an evaluator turns a prepared input into a decision, how a reusable validity contract is checked, and how signatures and signing keys are verified.

A third party can build a conformant evaluator and verifier from this text and the data model in [`conformance/cddl/kernel.cddl`](../../conformance/cddl/kernel.cddl). No implementation code is needed or referenced.

## Parts

| File | Contents |
|---|---|
| [`encoding.md`](encoding.md) | Deterministic CBOR profile, structural limits, the strict JSON profile, digests and domain separation, record envelopes, Merkle trees |
| [`algebra.md`](algebra.md) | Values and selectors, the nine closed bound types, `⊑` / `∩` / `normalize`, authority sets, the child-within-parent check |
| [`evaluation.md`](evaluation.md) | The evaluation input, intent coverage, requirement resolution, the decision combinator, blockers, fuel, rejections versus decisions |
| [`validity.md`](validity.md) | The validity contract and the checks a verifier applies to it |
| [`signatures.md`](signatures.md) | COSE_Sign1, JWS and SD-JWT verification profiles, Ed25519 and ECDSA strictness, operational key scope and Domain Metadata |

## Conventions

<a id="L0-GEN-1"></a>**L0-GEN-1.** The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and "OPTIONAL" are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals.

<a id="L0-GEN-2"></a>**L0-GEN-2.** Every normative rule has a stable anchor of the form `L0-<PART>-<n>`, where `<PART>` is `GEN`, `ENC`, `ALG`, `EVAL`, `VAL` or `SIG`. Anchors are never reused or renumbered. A withdrawn rule keeps its anchor and is marked as withdrawn.

<a id="L0-GEN-3"></a>**L0-GEN-3.** Field names, type names and choice names in `code` refer to the CDDL. Where this text and the CDDL describe the same structure, both MUST hold. A conflict between them is a defect in this text and is fixed before adoption.

<a id="L0-GEN-4"></a>**L0-GEN-4.** An item marked **OPEN** is not a rule. It records a question this version does not answer. An implementation MUST NOT rely on any particular answer to an OPEN item. Conformance vectors do not test OPEN items.

Notation: `‖` is byte concatenation. `SHA-256(x)` is the 32-byte digest of the bytes `x`. `dCBOR(v)` is the deterministic CBOR encoding of `v` defined in [`encoding.md`](encoding.md). `⊥` is the bottom value, which covers nothing. Times are TrustedTime values: milliseconds since the Unix epoch.

## Terms

| Term | Meaning in L0 |
|---|---|
| Domain | An authority domain. Identified by a DomainID, the digest of its genesis record. |
| Party | A person or organisation that can hold authority. Referenced by a 16-byte `party-ref`. |
| Instance | One running actor (a device, a session, an agent) that belongs to a Party. Referenced by a 16-byte `instance-ref`. |
| Grant | A record that gives authority to a holder. Its content is a `canonical-authority`. |
| Hop | One Grant in a lineage. Hop 0 is the requester's own Grant; hop k+1 is the Grant that hop k was delegated from. |
| Basis | The lineage the requester relies on: its hops, from hop 0 toward the root, and the capacities it permits. |
| Mandate | The limits an Instance itself is under, independent of any Grant. |
| Capacity | Whether the actor acts on its own behalf (`own`) or for another Party (`for`). |
| Intent | The exact action the actor wants to perform: an `intent-envelope`. |
| Proof | Evidence presented with a request: a claim, a contribution (approval), an authentication, or a foreign authority. |
| Restriction policy | A deny-only policy. It can object, require more proofs, or stay silent. It can never add authority. |
| Requirement term | One condition that proofs must satisfy before an action is allowed. |
| Blocker | One reason for a DENY, with its position, who can resolve it, and a remediation code. |

## Relation to the CDDL and the vectors

The CDDL file is the normative data model. This text gives the meaning of each structure and the rules that operate on it.

Conformance vectors live in [`conformance/vectors/`](../../conformance/vectors). Each vector file is JSON, carries its byte strings as lowercase hex, names a track and a version, and names the operation it exercises. Core track version 1 has these files and operations:

| File | Operation | Exercises |
|---|---|---|
| [`core/1/cbor-decode.json`](../../conformance/vectors/core/1/cbor-decode.json) | `dcbor.decode` | [L0-ENC-9a](encoding.md#L0-ENC-9a), [L0-ENC-10a](encoding.md#L0-ENC-10a), [L0-ENC-10b](encoding.md#L0-ENC-10b) |
| [`core/1/codec.json`](../../conformance/vectors/core/1/codec.json) | `codec.encode` | [L0-ENC-1](encoding.md#L0-ENC-1) to [L0-ENC-9](encoding.md#L0-ENC-9) |
| [`core/1/merkle.json`](../../conformance/vectors/core/1/merkle.json) | `digest.merkle` | [L0-ENC-30](encoding.md#L0-ENC-30) to [L0-ENC-33](encoding.md#L0-ENC-33) |
| [`core/1/decision.json`](../../conformance/vectors/core/1/decision.json) | `combinator.evaluate` | [`evaluation.md`](evaluation.md) |
| [`core/1/cve-regressions.json`](../../conformance/vectors/core/1/cve-regressions.json) | `combinator.evaluate`, `algebra.child_within_parent` | [`algebra.md`](algebra.md), [`evaluation.md`](evaluation.md) |
| [`core/1/cose.json`](../../conformance/vectors/core/1/cose.json) | `verify.cose_sign1` | [L0-SIG-10](signatures.md#L0-SIG-10) to [L0-SIG-21](signatures.md#L0-SIG-21) |
| [`core/1/jose-attack-classes.json`](../../conformance/vectors/core/1/jose-attack-classes.json) | `verify.jws_compact` | [L0-SIG-30](signatures.md#L0-SIG-30) to [L0-SIG-42](signatures.md#L0-SIG-42) |
| [`core/1/ed25519-strict.json`](../../conformance/vectors/core/1/ed25519-strict.json) | `verify.ed25519` | [L0-SIG-3](signatures.md#L0-SIG-3) |
| [`core/1/key-scope.json`](../../conformance/vectors/core/1/key-scope.json) | `key_scope.operational_key` | [L0-SIG-60](signatures.md#L0-SIG-60) to [L0-SIG-72](signatures.md#L0-SIG-72), [L0-SIG-75a](signatures.md#L0-SIG-75a) |
| [`core/1/jwt-claims.json`](../../conformance/vectors/core/1/jwt-claims.json) | `verify.jws_compact` | [L0-SIG-41](signatures.md#L0-SIG-41) to [L0-SIG-41b](signatures.md#L0-SIG-41b), [L0-ENC-15](encoding.md#L0-ENC-15) |
| [`core/1/sd-jwt.json`](../../conformance/vectors/core/1/sd-jwt.json) | `verify.sd_jwt` | [L0-SIG-50](signatures.md#L0-SIG-50) to [L0-SIG-53](signatures.md#L0-SIG-53) |
| [`core/1/validity.json`](../../conformance/vectors/core/1/validity.json) | `validity.check` | [L0-VAL-10](validity.md#L0-VAL-10) to [L0-VAL-11](validity.md#L0-VAL-11), [L0-VAL-14b](validity.md#L0-VAL-14b), [L0-VAL-16a](validity.md#L0-VAL-16a), [L0-VAL-16b](validity.md#L0-VAL-16b) |

<a id="L0-GEN-5"></a>**L0-GEN-5.** An implementation conforms to core version 1 only if it produces the expected result for every vector of every operation it implements. For `combinator.evaluate` the expected result is the exact bytes of the canonical `decision`, or the named rejection kind. For verification operations it is acceptance with the expected output, or rejection with the named reason.

<a id="L0-GEN-6"></a>**L0-GEN-6.** The normative definition of core semantics is this text together with the vectors. Where an implementation disagrees with them, the implementation is wrong.

Vectors are also checked against third-party sources where these exist: [`conformance/vectors/external/`](../../conformance/vectors/external) holds the Ed25519 edge cases from "Taming the many EdDSAs", Wycheproof Ed25519 and ECDSA P-256 sets, NIST ACVP SHA-256, EdDSA and ECDSA SigVer sets, and the RFC 9901 disclosure examples.

## Versioning

<a id="L0-GEN-7"></a>**L0-GEN-7.** Each layer has its own version track. A version takes effect only once adopted. A newer verifier MUST accept everything an older verifier of the same track accepted for the same input; the reverse is not required.

<a id="L0-GEN-8"></a>**L0-GEN-8.** An element an evaluator or verifier does not understand never widens authority. In new input it is rejected; in stored or external artifacts it is read as unknown and covers nothing ([L0-ALG-4](algebra.md#L0-ALG-4)).

## Open issues

No question is open in this draft.

### Closed in this draft

| # | Decided in |
|---|---|
| O-1 Intent validity | [L0-EVAL-5](evaluation.md#L0-EVAL-5) |
| O-2 Context strings | [L0-ENC-22](encoding.md#L0-ENC-22), [L0-ENC-22a](encoding.md#L0-ENC-22a) |
| O-3 DomainID | [L0-ENC-25](encoding.md#L0-ENC-25) |
| O-4 Depth counting | [L0-ENC-10a](encoding.md#L0-ENC-10a) |
| O-5 String limit | [L0-ENC-10b](encoding.md#L0-ENC-10b) |
| O-6 JSON size limits | [L0-ENC-15a](encoding.md#L0-ENC-15a) |
| O-7 Time windows | [L0-ALG-11](algebra.md#L0-ALG-11) |
| O-8 Duplicate entries | [L0-EVAL-3](evaluation.md#L0-EVAL-3) |
| O-9 Action set `∩` | [L0-ALG-33](algebra.md#L0-ALG-33) |
| O-10 Schema digest mismatch | [L0-EVAL-11](evaluation.md#L0-EVAL-11) |
| O-11 Overflow blocker | [L0-EVAL-50a](evaluation.md#L0-EVAL-50a) |
| O-12 `versions` | [L0-EVAL-43](evaluation.md#L0-EVAL-43) |
| O-13 Stored authority not understood | [L0-ALG-4a](algebra.md#L0-ALG-4a), [L0-EVAL-12a](evaluation.md#L0-EVAL-12a) |
| O-14 Assurance dimensions | [L0-ALG-60](algebra.md#L0-ALG-60), [L0-ALG-60a](algebra.md#L0-ALG-60a), [L0-ALG-60b](algebra.md#L0-ALG-60b), [L0-EVAL-25](evaluation.md#L0-EVAL-25) |
| O-15 Dependency bounds | [L0-VAL-5a](validity.md#L0-VAL-5a) |
| O-16 Horizon inclusive | [L0-VAL-11](validity.md#L0-VAL-11) |
| O-17 Clock skew | [L0-VAL-14](validity.md#L0-VAL-14), [L0-VAL-14a](validity.md#L0-VAL-14a), [L0-VAL-14b](validity.md#L0-VAL-14b) |
| O-18 Horizon ceiling | [L0-VAL-10a](validity.md#L0-VAL-10a), [L0-VAL-10b](validity.md#L0-VAL-10b) |
| O-19 Rejection order | [L0-SIG-21](signatures.md#L0-SIG-21) |
| O-29 JWS rejection order | [L0-SIG-21a](signatures.md#L0-SIG-21a) |
| O-20 JWS header | [L0-SIG-33](signatures.md#L0-SIG-33) |
| O-21 JWT times | [L0-SIG-41a](signatures.md#L0-SIG-41a) |
| O-22 `_sd_alg` | [L0-SIG-50](signatures.md#L0-SIG-50) |
| O-23 Hybrid policy | [L0-SIG-75a](signatures.md#L0-SIG-75a) |
| O-24 ML-DSA thumbprint | [L0-SIG-66](signatures.md#L0-SIG-66) |
| O-25 Blocker order | [L0-EVAL-41](evaluation.md#L0-EVAL-41) |
| O-26 Requirement order | [L0-EVAL-21](evaluation.md#L0-EVAL-21) |
| O-27 Rolling budget without reset | [L0-EVAL-15a](evaluation.md#L0-EVAL-15a) |
| O-28 `check` DENY content | [L0-EVAL-36](evaluation.md#L0-EVAL-36) |
