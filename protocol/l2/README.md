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
| Intent envelope | `intent-envelope` | carried inside other artefacts | not signed by itself | [L0-EVAL-5](../l0/evaluation.md#L0-EVAL-5) |

The data model is [`conformance/cddl/kernel.cddl`](../../conformance/cddl/kernel.cddl).

## Signing profile

<a id="L2-SIG-1"></a>**L2-SIG-1.** Every L2 artefact is a COSE_Sign1 whose protected header carries exactly `alg`, the content type and `kid`, as [L0-SIG-10](../l0/signatures.md#L0-SIG-10) requires. The payload is the deterministic CBOR encoding of the artefact.

<a id="L2-SIG-2"></a>**L2-SIG-2.** The default algorithm is Ed25519 (COSE `-19`). ES256 (`-9`) is also produced on request. A producer never signs an L2 artefact with RSA or with a realm JOSE key.

<a id="L2-SIG-3"></a>**L2-SIG-3.** A producer only signs with an operational key inside its excerpt window, and only for usages the excerpt names.

## Digest contexts

<a id="L2-DIG-1"></a>**L2-DIG-1.** Every digest an L2 artefact carries is computed by the producer from canonical CBOR under a context string from the table in [L0-ENC-22](../l0/encoding.md#L0-ENC-22). A verifier recomputes it and never takes a digest from the input.

## Later parts

These parts arrive with the features that produce them, each in its own version of this track:

| Part | Contents |
|---|---|
| Actor Intent Statement (AIS) | The signed statement of an actor's exact intent |
| Approval Act Statement (AAS) | A human approval bound to an intent digest |
| Portable Authority Proof (PAP) | An offline-checkable proof of authority with its embedded ValidityContract |
| Receipt | The signed record of a commit |
| Schema Publication Package | Action schemas and their catalog digests |
| Authority Record Exchange | Record transfer with checkpoints, handover and recovery |

## License

[Apache License 2.0](../../LICENSE).
