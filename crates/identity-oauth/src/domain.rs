//! Domain types and rules, free of I/O (OP-63).

pub mod authority;
pub mod client;
pub mod dpop;
pub mod issuer;
pub mod jwt;
pub mod login;
pub mod metadata;
pub mod request;
pub mod scope;
pub mod step_up;
pub mod suiss;
pub mod tokens;

#[cfg(test)]
mod tests;
