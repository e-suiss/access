# Access Conformance (L3)

This folder is the conformance layer of the Access Protocol: the data model, the test vectors, and a reference evaluator that anyone can run without Suiss. Everything here is free to use under the [Apache License 2.0](../LICENSE).

| Folder | Contents |
|---|---|
| [`cddl/`](cddl) | The normative data model ([`kernel.cddl`](cddl/kernel.cddl)) and the wire contracts shared with other products: the typed authority request ([`authority-request.cddl`](cddl/authority-request.cddl), with its [JSON Schema](cddl/authority-request.schema.json)), the Suiss discovery endpoints ([`suiss-discovery.cddl`](cddl/suiss-discovery.cddl)), the signed key lookup answer ([`key-lookup.cddl`](cddl/key-lookup.cddl)), its twin the signed Party status lookup answer ([`party-lookup.cddl`](cddl/party-lookup.cddl)) the decision explanation every Suiss product answers in ([`explanation.cddl`](cddl/explanation.cddl), with its [JSON Schema](cddl/explanation.schema.json)), and the edge contracts: the sandboxed parser worker's protocol ([`parser-worker.cddl`](cddl/parser-worker.cddl)) the gateway channel to the server ([`edge-channel.cddl`](cddl/edge-channel.cddl)), the SCIM Security Event Token claims ([`scim-set.cddl`](cddl/scim-set.cddl)) and the SAML/SCIM divergence profile data format ([`interop-profile.cddl`](cddl/interop-profile.cddl), with its [JSON Schema](cddl/interop-profile.schema.json)), each with checked [examples](cddl/examples) |
| [`vectors/`](vectors) | Test vectors by track and version, plus third-party sets in [`vectors/external/`](vectors/external) |
| [`reference/f0/`](reference/f0) | F0, a naive reference evaluator written from the protocol text alone |
| [`lean/`](lean) | An executable Lean model of the constraint algebra with machine-checked proofs |
| [`catalog/`](catalog) | Invariants, guarantees and claims the vectors and tests are traced to |
| [`pep/`](pep) | PEP fault cases and a language-independent runner: no upstream fault may produce an effect |
| [`interop/`](interop) | The interop lab: the systems Access is tested against, the public [compatibility table](interop/COMPATIBILITY.md) and the differential tests |

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
| [Reference Verifier](../bins/access-verify) (`access-verify`) | `cargo nextest run -p esuiss-access-verify` |
| TypeScript (Wasm) binding | `just web-test` |
| Python (uniffi) binding | `just uniffi-test` |
| Independent CBOR check (Go and Python) | `just vectors-crosscheck` |

The Kernel and F0 are also compared every night on random inputs (`just f0-random <count> <seed>`). Any difference fails the run.

## External suites in CI

These suites run side by side, and none stands in for another: the Access vectors test Access semantics, the others test wire formats and interoperability.

| Suite | Runs against | Where |
|---|---|---|
| Access vectors | every Kernel binding and F0 | every pull request |
| [OpenID Foundation conformance suite](oidf) | a seeded realm: Basic OP, Config OP, FAPI 2.0 Security Profile and Message Signing, FAPI-CIBA (poll and ping), Dynamic OP, RP-initiated, back-channel and front-channel logout, and OpenID Federation | every night and every release tag (`oidf-conformance`) |
| [Differential tests](interop) | Access next to oidc-provider, openid-client, xmlsec1, SimpleSAMLphp, Shibboleth SP and scim2-tester | every night and every release tag (`differential`) |
| [Interop lab](interop) | recorded vendor requests through the real parsers and servers | every night and every release tag (`interop-lab`) |
| [SAML IdP test suite](../tools/saml-idp-suite) | the SAML identity provider: standards checks, signature wrapping and comment injection, service provider profiles | every build |
| [MCP conformance suite](mcp), pinned in its lockfile | the local deployment's authorization server, and the Rust SDK's reference MCP resource server on the same deployment | every image built from `main` (`mcp-conformance`) |

## Claiming conformance

An implementation conforms to a track version when it produces the expected result for every case of every operation it implements in that version ([L0-GEN-5](../protocol/l0/README.md)). A claim names the track, the version and the operations covered. Vectors are only added to a published version, never changed; a fix to an expected result is a new version.

## Event names

[`catalog/events.toml`](catalog/events.toml) lists the permanent names of the events Access logs (`grant.issued`, `login.failed`, `api.throttled`, …). Alerts, dashboards and the OCSF and CAEP mappings rely on them, so a published name is never renamed or removed: a changed meaning gets a new name, and the old entry stays with `deprecated = true`. Each entry has:

| Field | Meaning |
|---|---|
| `name` | dotted lowercase name, `<subject>.<verb>[.<detail>]` |
| `plane` | `authority`, `identity`, `signer` or `ops` |
| `severity` | the level it is logged at: `debug`, `info`, `warn` or `error` |
| `since` | the release that first logs it, or `unreleased` until a release stamps it |
| `fields` | its own fields besides the common ones every line carries (`trace_id`, `span_id`, `service`, `version`, `event`, `outcome`); never a body, a secret or personal data |
| `ocsf` | the OCSF class it maps to |
| `caep` | the CAEP or RISC event type it maps to, when one fits |

`cargo xtask check` refuses an event name in the code that is not listed here.

## Releases

Each released version of the vectors and of F0 is published as an archive with its SHA-256 and a build attestation. Every released F0 stays available, so an old decision can be replayed with the evaluator of its own version.
