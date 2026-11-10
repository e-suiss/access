# Product seams

How domain products connect to Access: each one through the same contract, built on the public crates and the public endpoints only.

- `schemas/` holds one seam schema per product: its action namespace, typed Action Schemas, parameter classes and the Claim classes it issues. Suiss Ride and Suiss Health are hypothetical products that show a new product needs no new primitive; Pay, Commerce and Serve are filled as their seams land.
- `declared.toml` lists what each auxiliary service still depends on beyond its crates and endpoints.
- `DEPENDENCIES.md` is generated from the code and `declared.toml` by `cargo xtask seam-dependencies`; `cargo xtask check no-privileged-path` fails when it is stale, when a service depends on an unpublished crate, when anything in Access depends on a service, or when the product twin names an endpoint outside the public contracts.

The decisions of Ride and Health are also Kernel vectors under `conformance/vectors/seams/`, checked by the F0 reference evaluator.
