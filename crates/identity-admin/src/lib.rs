//! Identity plane configuration through `idp.*` domain actions (CMP-15.5, MD-14, E34).
//!
//! The identity plane is the PEP of its own configuration: it builds the intent of a change,
//! has the realm's governing domain commit it through `internal-api`, and writes the change
//! only against the committed ALLOW, in a transaction the database checks (EI-25, TN-110).
//! Creating a realm opens its governing domain first (TN-111).

pub mod app;
pub mod domain;
pub mod ports;

use access_crypto::opaque_id::OpaqueIdError;
use access_identity_oauth::domain::issuer::IssuerError;
use access_store::StoreError;

use crate::domain::Invalid;

/// Why a configuration operation did not happen. A refused Exercise is a decision, not an error
/// ([`app::Applied::NotAllowed`]).
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The change is not valid.
    #[error(transparent)]
    Invalid(#[from] Invalid),
    /// The slug or issuer is not valid (TN-16).
    #[error("issuer: {0}")]
    Issuer(#[from] IssuerError),
    /// No such active realm in this tenant.
    #[error("no such realm")]
    NoRealm,
    /// The authority plane gave no decision.
    #[error("refused: {0}")]
    Refused(String),
    /// The authority plane could not be reached.
    #[error("authority plane unavailable: {0}")]
    Unavailable(String),
    /// The committed decision is not about this change in this realm's domain (EI-25).
    #[error("decision does not bind the change")]
    Unbound,
    /// The state changed between the check and the write.
    #[error("conflict")]
    Conflict,
    /// An external id could not be formed.
    #[error("opaque id: {0}")]
    OpaqueId(#[from] OpaqueIdError),
    /// The change could not be encoded.
    #[error("encoding")]
    Encode,
    /// Storage failed; nothing was written.
    #[error("store: {0}")]
    Store(#[from] StoreError),
}

impl AdminError {
    /// HTTP status and stable reason code of the RFC 9457 problem.
    #[must_use]
    pub const fn problem(&self) -> (u16, &'static str) {
        match self {
            Self::Invalid(i) => (400, i.code()),
            Self::Issuer(_) => (400, "invalid-slug"),
            Self::NoRealm => (404, "no-such-realm"),
            Self::Refused(_) => (400, "exercise-refused"),
            Self::Conflict => (409, "conflict"),
            Self::Unbound => (500, "decision-mismatch"),
            Self::Unavailable(_) | Self::Store(_) | Self::OpaqueId(_) | Self::Encode => {
                (503, "temporarily-unavailable")
            }
        }
    }
}
