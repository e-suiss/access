# Access Conformance (L3)

This folder is the conformance layer of the Access Protocol: the data model, the test vectors, and a reference evaluator that anyone can run without Suiss. Everything here is free to use under the [Apache License 2.0](../LICENSE).

| Folder | Contents |
|---|---|
| [`cddl/`](cddl) | The normative data model ([`kernel.cddl`](cddl/kernel.cddl)) |
| [`vectors/`](vectors) | Test vectors by track and version, plus third-party sets in [`vectors/external/`](vectors/external) |
| [`reference/f0/`](reference/f0) | F0, a naive reference evaluator written from the protocol text alone |
| [`lean/`](lean) | An executable Lean model of the constraint algebra with machine-checked proofs |
| [`catalog/`](catalog) | Invariants, guarantees and claims the vectors and tests are traced to |

## Vector format

A vector file is JSON. Its header names:

- `track` and `version`: the protocol track the cases belong to (for example `core`, `1`);
- `operation`: the operation every case exercises, for example `combinator.evaluate` or `verify.cose_sign1`;
- `rule`: the decisions the cases come from.

Each case has a `name`, its inputs and the expected result. Byte strings are lowercase hex. The expected result is either exact output bytes or a named rejection, so two implementations can be compared byte for byte.

## Running the vectors

| Implementation | Command |
|---|---|
| Rust Kernel | `just test` |
| F0 reference evaluator | `just f0` |
| TypeScript (Wasm) binding | `just web-test` |
| Python (uniffi) binding | `just uniffi-test` |
| Independent CBOR check (Go and Python) | `just vectors-crosscheck` |

The Kernel and F0 are also compared every night on random inputs (`just f0-random <count> <seed>`). Any difference fails the run.

## Claiming conformance

An implementation conforms to a track version when it produces the expected result for every case of every operation it implements in that version ([L0-GEN-5](../protocol/l0/README.md)). A claim names the track, the version and the operations covered. Vectors are only added to a published version, never changed; a fix to an expected result is a new version.

## Releases

Each released version of the vectors and of F0 is published as an archive with its SHA-256 and a build attestation. Every released F0 stays available, so an old decision can be replayed with the evaluator of its own version.
