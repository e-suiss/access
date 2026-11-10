//! OpenID Federation 1.0 for the identity plane, without I/O (§10.7.1, IDP-19, IDP-20,
//! OP-155 m.3 (j)): entity statement validation, trust chain validation and resolution,
//! metadata policy, trust marks, and the checks of automatic and explicit registration.
//! Time is always an argument; fetching is the caller's, through the guarded outbound client.

pub mod app;
pub mod domain;
pub mod ports;

#[cfg(test)]
mod testkit;

pub(crate) use domain::jws;
pub use domain::{build, chain, policy, request, statement, trust_mark};

pub use chain::{Chain, ChainError, Resolver, Step, TrustAnchor};
pub use policy::PolicyError;
pub use statement::{EntityStatement, Jwk, OidfError};
pub use trust_mark::TrustMark;
