//! Typed authentication state machine, login sessions and epochs (CMP-15.2, OP-146 I5):
//! identifier-first sign-in (TN-96), the requirement model (TN-132), suspendable e-mail steps
//! (TN-102), the typed authentication result and assurance vector (TN-103, §10.1.6), opaque
//! session cookies (CR-38), device markers (X33), TOTP and recovery codes (§10.2.2) and the
//! three epochs (MD-7).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

use access_identity_account::AccountError;
use access_identity_account::domain::login::{Problem, unavailable};
use access_identity_account::notify::NotifyError;
use access_identity_risk::RiskError;
use access_identity_webauthn::WebAuthnError;
use access_store::StoreError;

pub use domain::flow::FlowRejection;

/// Why an authentication or session operation failed. Refused steps are decisions
/// ([`app::Step`]), not errors (OP-64).
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Storage failed; nothing was authenticated (fail closed, G48).
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// An account operation failed.
    #[error(transparent)]
    Account(#[from] AccountError),
    /// The WebAuthn relying party failed.
    #[error("webauthn: {0}")]
    WebAuthn(#[from] WebAuthnError),
    /// The Relay seam failed; the transaction rolls back.
    #[error("notify: {0}")]
    Notify(#[from] NotifyError),
    /// The request is malformed in a way that does not depend on any account.
    #[error("invalid request")]
    Invalid,
    /// Another request moved the flow first.
    #[error("flow changed concurrently")]
    Conflict,
    /// The random source failed.
    #[error("no randomness")]
    Random,
    /// Stored data does not match the model.
    #[error("stored data is malformed")]
    Corrupt,
    /// SL2 could not record its assessment; nothing was authenticated (MD-8).
    #[error("risk: {0}")]
    Risk(#[from] RiskError),
}

/// OP-45 rule 4, EP-1: the identity database cannot answer. Nobody is signed in, registered or
/// refreshed and nothing is revoked until it answers; the page says "Sign-in isn't available
/// right now" (`login.degraded`), never an allow.
pub const DEGRADED: Problem = Problem {
    status: 503,
    code: "degraded-identity",
    title: "Sign-in isn't available right now",
    retry_after_s: Some(1),
};

impl SessionError {
    /// The RFC 9457 problem. A database that cannot answer is [`DEGRADED`]; other dependency and
    /// capacity failures shed with `503 + Retry-After`; none ever authenticates (G48, G50).
    #[must_use]
    pub fn problem(&self) -> Problem {
        match self {
            Self::Store(_) | Self::Account(AccountError::Store(_)) => DEGRADED,
            Self::Notify(_)
            | Self::WebAuthn(WebAuthnError::Registry(_))
            | Self::Risk(RiskError::Store(_) | RiskError::Account(AccountError::Store(_))) => {
                unavailable(1)
            }
            Self::Account(e) => e.problem(),
            Self::Invalid => Problem {
                status: 400,
                code: "invalid-request",
                title: "The request is not valid",
                retry_after_s: None,
            },
            Self::Conflict => Problem {
                status: 409,
                code: "flow-conflict",
                title: "The sign-in changed; try again",
                retry_after_s: None,
            },
            Self::WebAuthn(_) | Self::Random | Self::Corrupt | Self::Risk(_) => Problem {
                status: 500,
                code: "internal",
                title: "Internal error",
                retry_after_s: None,
            },
        }
    }
}
