//! Restriction engine contract types; the engine is `suiss-restriction` (OP-104 m.1, OP-108 m.14).

use alloc::collections::BTreeSet;

use crate::digest::Digest;
use crate::model::{Id, RequirementTerm};

/// A restriction DENY (OP-108 m.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDeny {
    /// Policy.
    pub policy: Id,
    /// Policy version digest.
    pub version: Digest,
    /// Whether the reason is hidden from the requester (`@undisclosed`).
    pub undisclosed: bool,
}

/// Output of one forbid-only policy (§5.8, OP-104 m.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestrictionOutcome {
    /// No objection.
    NoObjection,
    /// Denied.
    Deny(PolicyDeny),
    /// Allowed once these requirements are met.
    Require(BTreeSet<RequirementTerm>),
}
