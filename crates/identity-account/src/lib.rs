//! Identity subjects, identifiers, credentials and the account life cycle (CMP-15.3): the
//! TN-49 state machine, the credential store under per-subject DEKs (OP-42, OP-145), Argon2id
//! passwords (CR-36, CR-37), the breached-password check (IDP-3) and login throttling
//! (OP-35, SA-30), and the Access side of the Relay seam (E42, OP-146 m.2).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod notify;
pub mod ports;

use access_crypto::opaque_id::OpaqueIdError;
use access_store::StoreError;
use suiss_crypto::envelope::EnvelopeError;

use crate::domain::login::{Problem, unavailable};
use crate::domain::password::{HashFailure, PasswordRejected};
use crate::domain::status::InvalidTransition;

/// Why an account operation failed. Refused logins are decisions, not errors
/// ([`domain::login::PasswordLogin`]).
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// Storage failed; the operation did not happen.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// Key wrapping or sealing failed.
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    /// An external id could not be formed.
    #[error("opaque id: {0}")]
    OpaqueId(#[from] OpaqueIdError),
    /// A status change outside TN-49.
    #[error(transparent)]
    Transition(#[from] InvalidTransition),
    /// No such account in this realm.
    #[error("no such account")]
    NotFound,
    /// The realm already has this identifier.
    #[error("identifier taken")]
    IdentifierTaken,
    /// The credential is the account's last method (TN-68).
    #[error("last authentication method")]
    LastMethod,
    /// A new password breaks the policy.
    #[error("password rejected: {0}")]
    Password(#[from] PasswordRejected),
    /// Hashing failed.
    #[error("hash: {0}")]
    Hash(#[from] HashFailure),
    /// The hash semaphore stayed full for the whole wait (CR-36 m.3).
    #[error("hash capacity exhausted")]
    Busy,
    /// The breached-password check could not run (IDP-3, G50).
    #[error("breach check unavailable")]
    BreachUnavailable,
    /// The random source failed.
    #[error("no randomness")]
    Random,
    /// Stored data does not match the model.
    #[error("stored data is malformed")]
    Corrupt,
}

impl AccountError {
    /// The RFC 9457 problem. Capacity and dependency failures shed with `503 + Retry-After`
    /// (OP-36); none of them is ever an allow.
    #[must_use]
    pub const fn problem(&self) -> Problem {
        match self {
            Self::Busy | Self::BreachUnavailable | Self::Store(_) => unavailable(1),
            Self::NotFound => Problem {
                status: 404,
                code: "account-not-found",
                title: "No such account",
                retry_after_s: None,
            },
            Self::IdentifierTaken => Problem {
                status: 409,
                code: "identifier-taken",
                title: "The identifier is taken",
                retry_after_s: None,
            },
            Self::LastMethod => Problem {
                status: 409,
                code: "last-method",
                title: "The last sign-in method cannot be removed",
                retry_after_s: None,
            },
            Self::Transition(_) => Problem {
                status: 409,
                code: "invalid-transition",
                title: "The account cannot move to that status",
                retry_after_s: None,
            },
            Self::Password(p) => Problem {
                status: 422,
                code: p.code(),
                title: "The password cannot be used",
                retry_after_s: None,
            },
            Self::Envelope(_)
            | Self::OpaqueId(_)
            | Self::Hash(_)
            | Self::Random
            | Self::Corrupt => Problem {
                status: 500,
                code: "internal",
                title: "Internal error",
                retry_after_s: None,
            },
        }
    }
}
