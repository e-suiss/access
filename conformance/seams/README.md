# Product seams

How domain products connect to Access: each one through the same contract, built on the public crates and the public endpoints only.

- `schemas/` holds one seam schema per product: its action namespace, typed Action Schemas, parameter classes and the Claim classes it issues. Suiss Ride and Suiss Health are hypothetical products that show a new product needs no new primitive; Relay's critical interrupt is a Grant on the person's self-anchor. Pay, Commerce and Serve keep their own truth (money and holds, orders and refund rules, shifts), and Access holds only the authority over their actions.
- `declared.toml` lists what each auxiliary service still depends on beyond its crates and endpoints.
- `DEPENDENCIES.md` is generated from the code and `declared.toml` by `cargo xtask seam-dependencies`; `cargo xtask check no-privileged-path` fails when it is stale, when a service depends on an unpublished crate, when anything in Access depends on a service, or when the product twin names an endpoint outside the public contracts.

The decisions of Ride, Health, Pay, Commerce and Serve are also Kernel vectors under `conformance/vectors/seams/`, checked by the F0 reference evaluator.
