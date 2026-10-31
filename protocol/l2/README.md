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

<a id="L2-REC-2"></a>**L2-REC-2.** Only a `decision` record whose outcome is `allow`, and a `claim` record whose disposition is `admit`, carry `effects`; a `claim` record's effects touch only `claim` keys. Any other record that carries `effects` is malformed. Within one record a key appears in at most one effect. A key is 1 to 512 bytes.

<a id="L2-REC-3"></a>**L2-REC-3. State fold.** The state of a domain at position `p` is the fold of the `effects` of records `1..p` in position order: a key's value is the value of the last effect for it, and its version is that record's position. An effect without a value leaves the key absent with that version. No other input changes the state; a replica, index or cache that disagrees with the fold is wrong.

Vectors: [`core/1/record-fold.json`](../../conformance/vectors/core/1/record-fold.json), operation `record.fold`: each case gives the records in position order as canonical envelopes and the resulting state as `[key, value, version]` triples sorted by key bytes (`value` is `null` in the JSON for an absent key), or the rejection.

## Actor Intent Statement

The Actor Intent Statement (AIS) is how an actor makes an Exercise its own. A PEP forwards it and cannot produce it. Without one, the actor is anonymous and holds only what `Public` holds.

<a id="L2-AIS-1"></a>**L2-AIS-1. Content.** An AIS is a COSE_Sign1 with content type `application/access-ais+cbor` whose payload is an `actor-intent-statement`: the DomainID, the nonce (16 to 64 bytes), the intent digest ([L0-ENC-23](../l0/encoding.md#L0-ENC-23)), the mode, the PEP's identity as the actor addressed it, the capacity, the basis, the signing time `iat` and, for `continue`, the ExerciseID. A payload of another shape is rejected (reason `ais-payload`).

<a id="L2-AIS-2"></a>**L2-AIS-2. Key.** The AIS verifies under the actor Instance's current key, with `kid` its RFC 7638 thumbprint, under the profile of [L0-SIG-10](../l0/signatures.md#L0-SIG-10). An Access actor is a native signer: a high-S ECDSA signature is rejected. Any other key, including a key the Instance has rotated away from, is rejected (reason `ais-signature`).

<a id="L2-AIS-3"></a>**L2-AIS-3. Binding.** Every signed field equals the request: the domain addressed, the nonce, the intent digest the receiver computes itself, the mode, the PEP's transport-authenticated identity, the capacity, the basis and, for `continue`, the ExerciseID. A difference is a protocol error, not a decision, and names the first differing field in that order (reason `ais-mismatch`).

<a id="L2-AIS-4"></a>**L2-AIS-4. Time.** An AIS whose `iat` is more than 60 seconds after the receiver's trusted time is rejected (reason `ais-future`). How old an AIS may be is decided by the nonce rule of [L2-REC-5](#L2-REC-5).

Vectors: [`core/1/ais.json`](../../conformance/vectors/core/1/ais.json), operation `ais.verify`: each case gives the COSE_Sign1, the request as an `actor-intent-statement` whose `iat` is ignored, and the trusted time; the file gives the Instance's key.

## Claims

A Claim is a signed statement by an issuer Party about a subject Party. It enters a decision only as a proof, and only when an Acceptance of the domain admits it; ingest alone never makes it count.

<a id="L2-CLM-1"></a>**L2-CLM-1. Content.** A Claim is a COSE_Sign1 with content type `application/access-claim+cbor` whose payload is a `claim-statement`. Its ClaimID is the first 16 bytes of `SHA-256("access/claim/v1" ‖ 0x00 ‖ the COSE_Sign1 bytes as received)`. A payload of another shape, or a Claim for another domain, is rejected (reason `claim-payload`).

<a id="L2-CLM-2"></a>**L2-CLM-2. Key.** The Claim verifies under the current key of an Instance of its issuer, with `kid` the key's RFC 7638 thumbprint, under the profile of [L0-SIG-10](../l0/signatures.md#L0-SIG-10); a high-S ECDSA signature is rejected. Any other key is rejected (reason `claim-signature`). A rejected Claim is a protocol error and is not recorded.

<a id="L2-CLM-3"></a>**L2-CLM-3. Disposition.** A verified Claim whose `issued_at` is more than 60 seconds after trusted time is `quarantine:future`. Otherwise it is `admit` when an Acceptance that has not ended covers it at the record's time: use `predicate-input`, the same issuer, its class among `classes`, its subject within `subject` (a Party or `Public`), the record time within `validity` and not after `ingest_until`, and its assurance meeting `assurance_floor`; else it is `quarantine:source-not-accepted`. Only an admitted Claim is a proof, and a recorded Claim is a proof only while an Acceptance still covers it.

<a id="L2-CLM-4"></a>**L2-CLM-4. Claim record.** Each Claim carried by a request is written as a record of kind `claim` with the fields of `claim-fields`, before the opening and decision records of the same batch, and its bytes go to the proof store. An admitted Claim's record sets its `claim-state`. An admitted ClaimID is not written again; a Claim held in quarantine may be sent again and gets a new record with a new disposition.

## Exercise records

<a id="L2-REC-4"></a><!-- no-vector: definition: the field set of the opening record; its use is in L2-REC-5 -->**L2-REC-4. Opening record.** Each evaluation in `commit` or `continue` writes a record of kind `opening` with the fields of `opening-fields` (nonce, actor Instance or `"anonymous"`, basis, capacity, intent digest, AIS digest, proof commitments and, for `continue`, the ExerciseID), followed in the same batch by its `decision` record. A re-evaluation of an open nonce writes only a new `decision` record.

<a id="L2-REC-5"></a><!-- no-vector: outside-operation: the nonce table is the commit path's, not an evaluator operation -->**L2-REC-5. Nonce.** A nonce belongs to one intent digest and one actor in its domain. Its outcomes form an append-only sequence: `allow` and `deny` are terminal and nothing follows them; `require_action` leaves it open until the intent's validity ends. The same nonce, intent and actor after a terminal outcome returns that outcome's records again. The same nonce with another intent or actor is a protocol error. An AIS whose nonce is new is accepted only while its age is within the intent validity ceiling.

## Signing profile

<a id="L2-SIG-1"></a>**L2-SIG-1.** Every L2 artefact is a COSE_Sign1 whose protected header carries exactly `alg`, the content type and `kid`, as [L0-SIG-10](../l0/signatures.md#L0-SIG-10) requires. The payload is the deterministic CBOR encoding of the artefact.

<a id="L2-SIG-2"></a>**L2-SIG-2.** The default algorithm is Ed25519 (COSE `-19`). ES256 (`-9`) is also produced on request. A producer never signs an L2 artefact with RSA or with a realm JOSE key.

<a id="L2-SIG-3"></a>**L2-SIG-3.** A producer only signs with an operational key inside its excerpt window, and only for usages the excerpt names.

## Digest contexts

<a id="L2-DIG-1"></a>**L2-DIG-1.** Every digest an L2 artefact carries is computed by the producer from canonical CBOR under a context string from the table in [L0-ENC-22](../l0/encoding.md#L0-ENC-22). A verifier recomputes it and never takes a digest from the input.

## Checkpoints

A checkpoint is the signed tree head of a log. Access uses the C2SP formats as published in their v1.1.0 family: [`signed-note`](https://c2sp.org/signed-note), [`tlog-checkpoint`](https://c2sp.org/tlog-checkpoint) and [`tlog-cosignature`](https://c2sp.org/tlog-cosignature). The rules below restate the parts a verifier needs; where they differ from C2SP, C2SP wins.

<a id="L2-CKP-1"></a>**L2-CKP-1. Checkpoint body.** The body has at least three lines, each ending in a newline: the log origin; the tree size as ASCII decimal without leading zeros (`0` for an empty tree); the RFC 9162 root hash in standard base64 with padding. Any further lines are extension lines and are non-empty. The origin is non-empty UTF-8 of at most 255 bytes without whitespace, `+` or control characters. A body that breaks these rules is rejected (reason `checkpoint-malformed`).

<a id="L2-CKP-2"></a>**L2-CKP-2. Note syntax.** A note is the body, one empty line, then one or more signature lines `— <name> <base64>` (the dash is U+2014), each ending in a newline. The body is UTF-8 without control characters other than newline (reason `note-control`). Base64 is standard with padding and only its canonical spelling is accepted. The decoded signature starts with a four-byte big-endian key ID. Two lines with the same name and key ID are rejected (reason `note-duplicate`). A verifier accepts at least 16 and at most 64 signature lines. Anything else is `note-malformed`.

<a id="L2-CKP-3"></a>**L2-CKP-3. Known keys.** A verifier knows each key by name, key ID and public key. The key ID of an Ed25519 key is the first four bytes of `SHA-256(name ‖ 0x0A ‖ type ‖ key)`, with type `0x01` for a log key and `0x04` for a cosigner. Signature lines from unknown keys are ignored. A line from a known key that does not verify rejects the note. A checkpoint is accepted only when the log's own Ed25519 signature over the body verifies (reason `note-unverified` otherwise) and the origin is the one the verifier expects.

<a id="L2-CKP-4"></a>**L2-CKP-4. Cosignatures.** A witness cosignature is `timestamp ‖ signature`: an eight-byte big-endian POSIX timestamp in seconds, then an Ed25519 signature over the lines `cosignature/v1`, `time <timestamp>` and the whole checkpoint body, extension lines included. The timestamp a verifier reports is the one that was signed.

Vectors: [`exchange/1/checkpoint.json`](../../conformance/vectors/exchange/1/checkpoint.json), operation `note.checkpoint`: each case gives a note and either the checkpoint it carries (size, root, number of extension lines, cosignature timestamps) or the rejection reason.

## Later parts

These parts arrive with the features that produce them, each in its own version of this track:

| Part | Contents |
|---|---|
| Actor Intent Statement (AIS) | The signed statement of an actor's exact intent |
| Approval Act Statement (AAS) | A human approval bound to an intent digest |
| Portable Authority Proof (PAP) | An offline-checkable proof of authority with its embedded ValidityContract |
| Receipt | The signed record of a commit |
| Schema Publication Package | Action schemas and their catalog digests |
| Authority Record Exchange | Record transfer, handover and recovery |

## License

[Apache License 2.0](../../LICENSE).
