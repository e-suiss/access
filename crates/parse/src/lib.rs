//! Bounded parsers for untrusted input (CR-10): every reader has size and depth limits.

pub mod cbor;
pub mod der;
pub mod json;
pub mod scim;
pub mod spnego;
