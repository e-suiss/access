//! Domain types and rules, free of I/O (OP-63).

pub mod assurance;
pub mod attestation;
pub mod authenticator_data;
pub mod ceremony;
pub mod client_data;
pub mod cose;
pub mod credential;
pub mod decoy;
pub mod ids;
pub mod mds;
pub mod options;
pub mod policy;
pub mod prf;
pub mod rejection;
pub mod rp;

pub use rejection::Rejection;
