//! Domain types and rules, free of I/O (OP-63).

pub mod authority;
pub mod ciba;
pub mod cimd;
pub mod claims_request;
pub mod client;
pub mod dcr;
pub mod device;
pub mod dpop;
pub mod exchange;
pub mod fapi;
pub mod issuer;
pub mod jarm;
pub mod jwe;
pub mod jwt;
pub mod login;
pub mod management;
pub mod metadata;
pub mod request;
pub mod scope;
pub mod step_up;
pub mod suiss;
pub mod tokens;

#[cfg(test)]
mod tests;
