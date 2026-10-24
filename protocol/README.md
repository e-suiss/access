# Access Protocol

The Access Protocol is an open, vendor-neutral and royalty-free specification for authority: who may do what, on whose behalf, and how anyone can check that decision later. This repository's code is one implementation of it. When the code and the protocol text disagree, the protocol text and its conformance vectors win.

## Layers

| Layer | Contents | Status |
|---|---|---|
| **L0 Core Semantics** | Records, values and meta-actions; the closed attenuation type system; evaluation rules (deny overrides, subsumption, lineage budget draw); record-fold; determinism; reasons and remediations | Normative |
| **L1 Interoperability Profiles** | How Access maps onto existing standards: AuthZEN decisions, OAuth/RAR/DPoP projections, SSF/CAEP signals, OIDC/SPIFFE/VC/SCIM claim ingest, OpenID Federation trust bootstrap, MCP and A2A | Normative |
| **L2 Access-native Parts** | Actor Intent Statement, Approval Act Statement, Portable Authority Proof with its ValidityContract, Schema Publication Package, Authority Record Exchange with checkpoints, handover and recovery | Normative |
| **L3 Conformance** | Criteria, test suites and vectors for providers, decision PEPs, offline verifiers, approval surfaces, claim issuers, schema publishers, coordinators and event receivers | Open |

L0, L1 and L2 live in this folder. L3 lives in [`conformance/`](../conformance): the data model in [`conformance/cddl/`](../conformance/cddl) and the test vectors in [`conformance/vectors/`](../conformance/vectors).

## Status

The protocol text is being written. The data model and the first vectors for L0 (deterministic CBOR, digests, Merkle trees, the constraint algebra, validity, signature verification and decisions) are already in `conformance/`.

Each layer has its own version track. A version that has not been adopted has no effect, and backward compatibility only runs one way: a newer verifier accepts what an older one accepted, never the reverse.

## License

[Apache License 2.0](../LICENSE). Anyone may implement the protocol without a fee or a license from Suiss.
