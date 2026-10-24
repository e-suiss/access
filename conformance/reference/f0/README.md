# F0 reference evaluator

F0 is a small, deliberately naive evaluator for the Access authorization protocol, written in Python. It serves as a differential oracle: it takes the same canonical CBOR `evaluation-input` as the Kernel and must produce byte-for-byte the same canonical `decision`.

F0 is written from the protocol specification and the CDDL in `conformance/cddl/kernel.cddl`, not from the Kernel source. It shares no code or libraries with the Kernel. CBOR is handled by `cbor2`, and everything else uses the standard library. The code favours readability over speed.

## Layout

| Module | Contents |
|---|---|
| `f0/codec.py` | Strict decoding: deterministic CBOR, no floats, tags or null, unknown fields rejected, sets sorted and unique, structural limits |
| `f0/algebra.py` | `⊑`, `∩` and `normalize` for the nine bound types, selectors, authority sets, and the child-within-parent check |
| `f0/intent.py` | Whether an authority set covers an intent |
| `f0/requirement.py` | The requirement resolver: proof matching, earliest-position selection, single-use consumption |
| `f0/combinator.py` | The decision combinator: blockers, modes, fuel, canonical decision encoding |
| `run.py` | Runs the conformance vectors |

## Running

Requires Python 3.12 or newer.

```sh
python -m venv .venv
.venv/bin/python -m pip install --require-hashes -r conformance/reference/f0/requirements.txt
.venv/bin/python -I conformance/reference/f0/run.py conformance/vectors
```

The runner walks every vector file, runs the cases whose operation F0 supports (`combinator.evaluate` and `algebra.child_within_parent`), prints `N passed, M failed` with each failure, and exits non-zero if anything failed.
