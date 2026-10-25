# F0 reference evaluator

F0 is a small, deliberately naive evaluator for the Access authorization protocol, written in Python. It serves as a differential oracle: it takes the same canonical CBOR `evaluation-input` as the Kernel and must produce byte-for-byte the same canonical `decision`.

F0 is written from the protocol specification and the CDDL in `conformance/cddl/kernel.cddl`, not from the Kernel source. It shares no code or libraries with the Kernel. CBOR is handled by `cbor2`. Signature verification is pure Python written from the standards (Ed25519 from RFC 8032, ECDSA P-256 from FIPS 186-5), with `hashlib` for SHA-256 and SHA-512. Everything else uses the standard library. The code favours readability over speed.

## Layout

| Module | Contents |
|---|---|
| `f0/dcbor.py` | Byte-by-byte deterministic CBOR check: shortest form, no indefinite lengths, floats, tags or simple values, key order, depth, item and string limits; the first error met wins |
| `f0/codec.py` | Strict decoding into the data model: unknown fields rejected, sets sorted and unique, CDDL types |
| `f0/algebra.py` | `⊑`, `∩` and `normalize` for the nine bound types, selectors, authority sets, and the child-within-parent check |
| `f0/intent.py` | Whether an authority set covers an intent |
| `f0/requirement.py` | The requirement resolver: proof matching, earliest-position selection, single-use consumption |
| `f0/combinator.py` | The decision combinator: blockers, modes, fuel, canonical decision encoding |
| `f0/ed25519.py` | Strict, cofactorless Ed25519 verification with canonical-encoding and small-order checks |
| `f0/p256.py` | ECDSA P-256 / SHA-256 verification and the high-S check |
| `f0/cose.py` | `COSE_Sign1` verification: tag, header profile, `crit`, algorithm allowlist, key lookup by `kid`, content type |
| `f0/keyscope.py` | Operational key resolution from Domain Metadata and a binding-signed key excerpt, including RFC 7638 thumbprints, CT horizon ceilings and the hybrid signature policy |
| `f0/jose.py` | Strict base64url and JSON, compact JWS verification in the profile's rejection order, JWT claims and times |
| `f0/sdjwt.py` | SD-JWT presentations (RFC 9901): disclosures, digest processing, decoys, `_sd_alg`, Key Binding JWT |
| `f0/validity.py` | Validity contracts: decoding, profile class and variant, must-understand, audience, skew, acceptance end, staleness and revalidation |
| `f0/merkle.py` | RFC 9162 tree hash, inclusion and consistency proofs |
| `f0/record.py` | Log record envelopes and selective disclosures: header rules, field commitments, field root, leaf hash, DomainID |
| `f0/version_check.py` | Version tracks: not understood, not adopted, below the domain minimum |
| `f0/digest.py` | Intent digest and body commitments |
| `f0/version.py` | The F0 release version and the core semantics version it implements |
| `run.py` | Runs the conformance vectors |

## Running

Requires Python 3.12 or newer.

```sh
python -m venv .venv
.venv/bin/python -m pip install --require-hashes -r conformance/reference/f0/requirements.txt
.venv/bin/python -I conformance/reference/f0/run.py conformance/vectors
```

The runner walks every vector file, runs the cases whose operation F0 supports, prints per-file counts and `N passed, M failed` with each failure, and exits non-zero if anything failed. `--summary <file>` also writes the counts as JSON.

Supported operations: `combinator.evaluate`, `algebra.child_within_parent`, `algebra.meet`, `codec.encode`, `dcbor.decode`, `digest.intent`, `digest.body_commit`, `digest.merkle`, `verify.cose_sign1`, `verify.ed25519`, `verify.jws_compact`, `verify.sd_jwt`, `verify.sd_jwt.disclosure`, `key_scope.operational_key`, `record.envelope`, `validity.check`, `validity.horizon` and `version.check`. A vector file whose operation F0 does not implement fails the run unless the operation is listed, with a reason, in `NOT_IMPLEMENTED` in `run.py` (empty today). Third-party data sets in `vectors/external/` that carry no `operation` are reported as skipped.

## Differential testing

`just f0-random <count> <seed>` has the Kernel generate random evaluation inputs together with its own decisions, then checks that F0 gives the same bytes for every one. The nightly workflow runs 20 shards of 500,000 inputs each, 10⁷ inputs a night, and publishes a `f0-drt-summary` artifact with the input and mismatch counts.

## Versions and replay

`f0/version.py` declares two numbers: `VERSION`, the F0 release, and `CORE_VERSION`, the core semantics version F0 implements. Vectors live under `conformance/vectors/core/<version>/`.

No published semantics version of F0 is ever retired. When the core semantics version changes, the F0 that implemented the old version is kept, unchanged, as a self-contained copy:

```
conformance/reference/f0/
├── f0/, run.py              current core version
└── versions/
    └── core-1/
        ├── f0/
        └── run.py           frozen F0 for core version 1
```

`run.py` dispatches on the vector directory: files under `core/<version>/` for an older version are run by `versions/core-<version>/run.py`, so one command checks every version that was ever published. A version without a retained F0 is a failure, not a skip. To replay a decision recorded under an older version, run that version's F0 on the recorded input. Every release also ships the exact F0 and vectors as archives (below), so a replay never depends on the current tree.

## Releases

F0 and the Kernel are released only from tags: `f0-v<VERSION>` and `kernel-v<version>`. The tag must match the declared version. The release workflow publishes nothing unless every condition holds:

- every vector passes in the Kernel and in F0;
- the latest nightly differential run compared at least 10⁷ inputs with no mismatch, and the Kernel, F0, vectors and CDDL have not changed since the commit it ran on;
- every Lean algebra theorem in `conformance/lean/proofs.toml` is `proved`.

A release carries `access-f0-<tag>.tar.gz` (this directory), `access-vectors-core-<version>-<tag>.tar.gz` (vectors and CDDL) and `SHA256SUMS`, with a GitHub artifact attestation (Sigstore build provenance) for each archive:

```sh
sha256sum -c SHA256SUMS
gh attestation verify access-f0-f0-v0.1.0.tar.gz --repo e-suiss/access
```
