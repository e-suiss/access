//! Domain types and rules, free of I/O (OP-63).

pub mod aaguid_hints;
pub mod assurance;
pub mod attestation;
pub mod authenticator_data;
pub mod ceremony;
pub mod client_data;
pub mod cose;
pub mod credential;
pub mod crl;
pub mod decoy;
pub mod ids;
pub mod mds;
pub mod options;
pub mod policy;
pub mod prf;
pub mod psl;
pub mod rejection;
pub mod rp;
pub mod software;
mod x509;

pub use rejection::Rejection;
