//! The OID4VP verifier service (OP-155 m.3 (p), IDP-21, E55): it asks a wallet for a
//! presentation under the HAIP profile (SD-JWT VC and mdoc, ES256, `direct_post.jwt`), checks it
//! against the trusted lists, and sends what it verified to Claim Ingest as a Claim signed with
//! its own Instance key; the presentation counts only where an Acceptance names the verifier. It
//! uses public crates only (OP-62) and holds no authority.
//!
//! [`domain`] is the pure core, [`app`] the use cases, [`store`] the verifier's own SQL module,
//! [`adapters`] the `/vc-verifier/v1/*` routes, and [`https`] the production
//! ports.

pub mod adapters;
pub mod app;
pub mod contract;
pub mod domain;
pub mod https;
pub mod ports;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;

pub use adapters::router;
