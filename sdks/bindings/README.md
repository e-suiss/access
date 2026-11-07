# Kernel bindings

Every Access SDK decides, verifies and encodes with the same Kernel. The bindings here expose it to other languages; none of them reimplements Kernel semantics.

| Binding | Directory | Languages | Vector run |
|---|---|---|---|
| uniffi | `uniffi/` | Python, Kotlin, Swift | `just uniffi-test`, `just uniffi-test-kotlin`, `just uniffi-test-swift` |
| WebAssembly | `wasm/` | TypeScript (Node and browsers) through `@esuiss/access` | `just web-test` |

A C ABI binding does not exist yet; it is added with the first language package that needs it, and joins the same gate.

## The gate

Each binding runs the conformance vectors in `conformance/vectors/core/1` on every pull request, and the `bindings-gate` CI job passes only when all of them did. The job writes one row of the table below to the run summary (`just bindings-row`): the Kernel version, the bindings that passed, and a hash of the vector set they passed.

## Compatibility

| Kernel | Bindings that passed the vectors | Vector set |
|---|---|---|
| 0.3.1 | uniffi (Python, Kotlin, Swift), Wasm (Node) | core/1 `49773693d68aea99` |

A binding version always equals the Kernel version it was built from. A vector set hash that changes without a Kernel version change means the vectors grew; every binding must pass the new set before release.

## License

[Apache License 2.0](../../LICENSE).
