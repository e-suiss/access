//! SL2 sign-in risk of the identity plane (§12.2.4 TN-46…TN-48, IDP-39, OP-151 m.1 (b), m.3 (n),
//! (o)).
//!
//! - SL0 are the cryptographic rejections that already block (DPoP, signatures, replay); SL1 is
//!   the deterministic requirement path (`RequirementTerm`, step-up, `REQUIRE_ACTION`). This crate is
//!   SL2: signals from the network, the device marker, the account's history, the login counters,
//!   the breach corpus and canary accounts, scored into `low`, `medium` or `high`.
//! - Risk only narrows (CI-2): its outputs are a `risk.level` Claim, a step-up request to the
//!   sign-in flow, a CAEP `risk-level-change` and a human review item. Never an allow, never a
//!   lock (GDPR art. 22).
//! - A missing source makes the level `unavailable`; the flow then runs on SL0 and SL1 alone and
//!   nothing it asks for is dropped (MD-8).
//! - Tenant analytics are daily counters per realm, never a decision input (TI-18).

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

use access_identity_account::AccountError;
use access_store::StoreError;

pub use domain::mode::InvalidMode;

/// Why a risk operation failed. An assessment's level, even `unavailable`, is a decision, not
/// an error (OP-64).
#[derive(Debug, thiserror::Error)]
pub enum RiskError {
    /// Storage failed; nothing was recorded and nothing was allowed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// Queuing a Claim or a signal failed.
    #[error(transparent)]
    Account(#[from] AccountError),
    /// The protection mode is not valid.
    #[error(transparent)]
    Mode(#[from] InvalidMode),
    /// Stored data does not match the model.
    #[error("stored data is malformed")]
    Corrupt,
}
