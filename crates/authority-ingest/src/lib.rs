//! CMP-8 Claim Ingest pipeline (§9.13, §10.1.2, OP-150 m.2): every carrier (a signed Claim, an
//! unsigned Claim over an authenticated channel, a WebAuthn ceremony, an upstream ID token, a
//! Security Event Token) becomes the same Claim record. The pipeline authenticates the issuer,
//! keeps only what a decision needs (E26), drops resubmissions, applies the issuer quota (G44)
//! and appends the `claim` record through the sequencer. It never changes authority state on its
//! own (PI-22) and never writes to the identity plane; ingest is not acceptance (INV-2).
//!
//! The authority plane serves [`access_internal_api::claims::ClaimIngest`] from this crate.

#![forbid(unsafe_code)]

pub mod app;
pub mod domain;
pub mod ports;
