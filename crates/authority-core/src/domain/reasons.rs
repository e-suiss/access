//! The `reason_user` ↔ `reason_admin` table (P41, §9.6.1, §8.17.8.2): for every explanation
//! category, the code the requester scope carries in `AuthZEN` `reason_user` (no free text, A-7)
//! and what the audit scope adds in `reason_admin`. `reason_admin` exists only for a caller with
//! audit authority; its presence is a disclosure (E26).

use access_kernel::combinator::BlockerClass;

/// What `reason_admin` may carry beyond the requester's view (§9.6.1: the audit scope).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdminDetail {
    /// The `StateBasis`: the objects read and their versions.
    StateBasis,
    /// Claims, Acceptances and policy versions the decision cited.
    Cited,
    /// The blocker's subcode, including an undisclosed restriction's policy reference.
    Subcode,
    /// The full lineage with identities in clear.
    Lineage,
    /// Consumption effects and budget draws.
    Consumption,
}

/// What the decision was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A DENY blocker.
    Deny,
    /// An unmet requirement of a `REQUIRE_ACTION`.
    Require,
}

/// One row of the table: an explanation category of §8.17.8.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reason {
    /// The category, as §8.17.8.2 names it.
    pub category: &'static str,
    /// DENY or `REQUIRE_ACTION`.
    pub kind: Kind,
    /// The X19 blocker class of a DENY row.
    pub blocker: Option<BlockerClass>,
    /// The proof kind a `REQUIRE_ACTION` row waits for.
    pub proof: Option<&'static str>,
    /// The `reason_user` code: a closed word, never text.
    pub user: &'static str,
    /// What `reason_admin` adds at audit scope.
    pub admin: &'static [AdminDetail],
}

use AdminDetail::{Cited, Consumption, Lineage, StateBasis, Subcode};

/// The table (P41; mapping PD).
pub const REASONS: [Reason; 14] = [
    Reason {
        category: "no covering authority",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::NoCoveringAuthority),
        proof: None,
        user: "no-covering-authority",
        admin: &[StateBasis, Lineage],
    },
    Reason {
        category: "outside instance limits",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::OutsideInstanceLimits),
        proof: None,
        user: "outside-instance-limits",
        admin: &[StateBasis, Subcode],
    },
    Reason {
        category: "restriction",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::Restricted),
        proof: None,
        user: "restricted",
        admin: &[StateBasis, Subcode, Cited],
    },
    Reason {
        category: "requirement missing: approval",
        kind: Kind::Require,
        blocker: None,
        proof: Some("contribution"),
        user: "requirement-approval",
        admin: &[StateBasis, Cited],
    },
    Reason {
        category: "requirement missing: step-up",
        kind: Kind::Require,
        blocker: None,
        proof: Some("authentication"),
        user: "requirement-step-up",
        admin: &[StateBasis, Cited],
    },
    Reason {
        category: "requirement missing: claim or posture",
        kind: Kind::Require,
        blocker: None,
        proof: Some("claim"),
        user: "requirement-claim",
        admin: &[StateBasis, Cited],
    },
    Reason {
        category: "stale statement (rule-shaped)",
        kind: Kind::Require,
        blocker: None,
        proof: Some("selection"),
        user: "requirement-selection",
        admin: &[StateBasis, Cited],
    },
    Reason {
        category: "budget exhausted",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::BudgetExhausted),
        proof: None,
        user: "budget-exhausted",
        admin: &[StateBasis, Consumption, Subcode],
    },
    Reason {
        category: "revoked, expired or ended",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::Ended),
        proof: None,
        user: "ended",
        admin: &[StateBasis, Subcode, Lineage],
    },
    Reason {
        category: "source not accepted",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::SourceNotAccepted),
        proof: None,
        user: "source-not-accepted",
        admin: &[StateBasis, Cited],
    },
    Reason {
        category: "schema version not accepted",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::SchemaNotAccepted),
        proof: None,
        user: "schema-not-accepted",
        admin: &[StateBasis, Cited],
    },
    Reason {
        category: "foreign status unknown",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::ForeignStatusUnavailable),
        proof: None,
        user: "foreign-status-unavailable",
        admin: &[StateBasis, Cited],
    },
    Reason {
        category: "capacity mismatch",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::CapacityMismatch),
        proof: None,
        user: "capacity-mismatch",
        admin: &[StateBasis, Lineage],
    },
    Reason {
        category: "nonce closed",
        kind: Kind::Deny,
        blocker: Some(BlockerClass::NonceClosed),
        proof: None,
        user: "nonce-closed",
        admin: &[StateBasis, Subcode],
    },
];

/// The row of a DENY blocker class.
#[must_use]
pub fn of_blocker(class: BlockerClass) -> Option<&'static Reason> {
    REASONS.iter().find(|r| r.blocker == Some(class))
}

/// The row of an unmet requirement waiting for `proof`.
#[must_use]
pub fn of_requirement(proof: &str) -> Option<&'static Reason> {
    REASONS.iter().find(|r| r.proof == Some(proof))
}

#[cfg(test)]
mod tests;
