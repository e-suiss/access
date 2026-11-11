//! HSM outage: the record commits, signing waits, and no unsigned artefact leaves (§16.7, TI-12).
//! The server-path proof is the signer fault of `signer.rs` (FO-08 in
//! `conformance/catalog/failure-ownership.toml`); the key factory outage that delays artefacts
//! past the key window is the authority signer's own test.
