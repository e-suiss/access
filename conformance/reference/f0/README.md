# F0 reference evaluator

F0 is a small, deliberately naive evaluator for the Access authorization protocol, written in Python. It serves as a differential oracle: it takes the same canonical CBOR `evaluation-input` as the Kernel and must produce byte-for-byte the same canonical `decision`.

F0 is written from the protocol specification and the CDDL in `conformance/cddl/kernel.cddl`, not from the Kernel source. It shares no code or libraries with the Kernel. CBOR is handled by `cbor2`. Signature verification is pure Python written from the standards (Ed25519 from RFC 8032, ECDSA P-256 from FIPS 186-5), with `hashlib` for SHA-256 and SHA-512. Everything else uses the standard library. The code favours readability over speed.

## Layout

| Module | Contents |
|---|---|
| `f0/codec.py` | Strict decoding: deterministic CBOR, no floats, tags or null, unknown fields rejected, sets sorted and unique, structural limits |
| `f0/algebra.py` | `⊑`, `∩` and `normalize` for the nine bound types, selectors, authority sets, and the child-within-parent check |
| `f0/intent.py` | Whether an authority set covers an intent |
| `f0/requirement.py` | The requirement resolver: proof matching, earliest-position selection, single-use consumption |
| `f0/combinator.py` | The decision combinator: blockers, modes, fuel, canonical decision encoding |
| `f0/ed25519.py` | Strict, cofactorless Ed25519 verification with canonical-encoding and small-order checks |
| `f0/p256.py` | ECDSA P-256 / SHA-256 verification and the high-S check |
| `f0/cose.py` | `COSE_Sign1` verification: tag, header profile, `crit`, algorithm allowlist, key lookup by `kid`, content type |
| `f0/keyscope.py` | Operational key resolution from Domain Metadata and a binding-signed key excerpt, including RFC 7638 thumbprints |
| `run.py` | Runs the conformance vectors |

## Running

Requires Python 3.12 or newer.

```sh
python -m venv .venv
.venv/bin/python -m pip install --require-hashes -r conformance/reference/f0/requirements.txt
.venv/bin/python -I conformance/reference/f0/run.py conformance/vectors
```

The runner walks every vector file, runs the cases whose operation F0 supports (`combinator.evaluate`, `algebra.child_within_parent`, `verify.cose_sign1`, `key_scope.operational_key` and `verify.ed25519`), prints per-file counts and `N passed, M failed` with each failure, and exits non-zero if anything failed.
