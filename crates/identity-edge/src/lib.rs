//! The access-server side of the edge channel (OP-155 m.3 (c), MD-1, IDP-26, IDI-11).
//!
//! A protocol gateway connects with its own client certificate, whose SAN URI names it
//! (`urn:suiss:access:gw:<kind>:<name>`). This crate finds the registered gateway, holds every
//! call to the gateway's realm and its kind's authentication method (§13.2 blast radius), and
//! turns an edge authentication into the realm issuer's `authentication` Claim. The gateway
//! signs nothing and never reaches the authority plane: the Claim is queued in the identity
//! plane's outbox and issued by the realm issuer (P-ID-5).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

/// Why an edge call was not answered.
#[derive(Debug, thiserror::Error)]
pub enum EdgeError {
    /// The call is outside the gateway's scope; the stable code says how.
    #[error("refused: {}", .0.code())]
    Refused(domain::Refusal),
    /// The certificate names no live registered gateway.
    #[error("gateway not registered")]
    NotRegistered,
    /// Storage failed; nothing happened.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

impl From<domain::Refusal> for EdgeError {
    fn from(r: domain::Refusal) -> Self {
        Self::Refused(r)
    }
}

impl From<access_identity_account::AccountError> for EdgeError {
    fn from(e: access_identity_account::AccountError) -> Self {
        Self::Unavailable(e.to_string())
    }
}

impl From<access_store::StoreError> for EdgeError {
    fn from(e: access_store::StoreError) -> Self {
        Self::Unavailable(e.to_string())
    }
}
