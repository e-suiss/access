# Interop lab

Access is tested against the systems it has to work with, and the public table of what was tested
is [`COMPATIBILITY.md`](COMPATIBILITY.md).

| File | Contents |
|---|---|
| [`lab.toml`](lab.toml) | The matrix: every system, its role, the version tested, how it runs, its interop profile and the tests that cover it |
| [`COMPATIBILITY.md`](COMPATIBILITY.md) | The public table, generated from the matrix by `cargo xtask interop-table` |
| [`fixtures/saml/`](fixtures/saml) | Service provider `AuthnRequest` shapes, unsigned |
| [`node/`](node) | openid-client against Access, and the corpus Access and oidc-provider must refuse alike |
| [`saml/`](saml) | The SimpleSAMLphp check of a real Access response |
| [`scim/`](scim) | The scim2-tester run and its expected list |

## How a system is tested

| Kind | Meaning |
|---|---|
| `container` | An open-source counterpart in a container pinned by digest, run on CI only and never part of an image |
| `package` | A distribution package on the CI runner |
| `fixture` | Requests recorded from the vendor, scrubbed of tenant names, signatures and secrets, or rebuilt from its published guide until a capture exists |
| `live` | A vendor test tenant, run only when its CI secret exists, through `scripts/ci/interop/live/<system>.sh` |

The jobs `differential` and `interop-lab` run every night and on every release tag; `edge-interop`
and `kerberos` run on every push. An oracle is a reference whose answer the differential tests
compare Access's with: only pinned open-source references are oracles, and Keycloak never is.

## Expected lists

A suite whose results include known differences records them, each with its reason: the OIDF
plans in [`../oidf/expected.json`](../oidf/expected.json), scim2-tester in
[`scim/expected.json`](scim/expected.json), the oidc-provider comparison in
[`node/expected.json`](node/expected.json). Until a list is recorded the suite is in its first
run: its failures are reported and the list to record is printed or uploaded. Once recorded, any
other failure fails the run, and a release refuses a suite whose list is not recorded. A
difference that disappears is reported so its entry can be removed.

## From a report to a profile

1. A report comes in through the interoperability issue template.
2. The failing message, scrubbed, becomes a test case.
3. If Access is wrong, the fix lands with that test. If the other system only insists on a
   format, its interop profile gets an entry (`conformance/cddl/interop-profile.cddl`) that names
   the test; a profile never relaxes a security check.
4. The system and version go into `lab.toml`, and `cargo xtask interop-table` regenerates the
   table.

`cargo xtask check` refuses a profile entry or a lab system whose test does not exist, an
unpinned container, a live row without its secret, Keycloak as an oracle, and a stale table.
