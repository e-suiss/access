#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_kernel::combinator::codec::decision_value;
use access_kernel::combinator::{Blocker, Decision, Outcome, Position, Remediation, Resolver};
use suiss_crypto::dcbor::Value;

use super::*;

/// The categories of §8.17.8.2, in its order, and the X19 class it has no row for.
const CATEGORIES: [&str; 14] = [
    "no covering authority",
    "outside instance limits",
    "restriction",
    "requirement missing: approval",
    "requirement missing: step-up",
    "requirement missing: claim or posture",
    "stale statement (rule-shaped)",
    "budget exhausted",
    "revoked, expired or ended",
    "source not accepted",
    "schema version not accepted",
    "foreign status unknown",
    "capacity mismatch",
    "nonce closed",
];

const CLASSES: [BlockerClass; 10] = [
    BlockerClass::NoCoveringAuthority,
    BlockerClass::OutsideInstanceLimits,
    BlockerClass::Restricted,
    BlockerClass::BudgetExhausted,
    BlockerClass::Ended,
    BlockerClass::CapacityMismatch,
    BlockerClass::SourceNotAccepted,
    BlockerClass::SchemaNotAccepted,
    BlockerClass::NonceClosed,
    BlockerClass::ForeignStatusUnavailable,
];

/// The wire word of a blocker class, as the Kernel encodes it.
fn word(class: BlockerClass) -> String {
    let d = Decision {
        outcome: Outcome::Deny,
        blockers: vec![Blocker {
            class,
            subcode: None,
            position: Position::Instance,
            resolver: Resolver::Actor,
            remediation: Remediation::NewRequestRequired,
        }],
        unmet: Vec::new(),
        relied_on: Vec::new(),
    };
    let v = decision_value(&d);
    match v.get("blockers") {
        Some(Value::Array(b)) => match b.first().and_then(|b| b.get("class")) {
            Some(Value::Text(t)) => t.clone(),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

// P41, §9.6.1, §8.17.8.2
#[test]
fn p41_every_explanation_category_has_one_row() {
    let names: Vec<&str> = REASONS.iter().map(|r| r.category).collect();
    assert_eq!(names, CATEGORIES);
}

// P41, X19
#[test]
fn p41_every_blocker_class_maps_to_its_wire_word() {
    for class in CLASSES {
        let rows: Vec<_> = REASONS
            .iter()
            .filter(|r| r.blocker == Some(class))
            .collect();
        assert_eq!(rows.len(), 1, "{class:?}");
        assert_eq!(of_blocker(class).unwrap().user, word(class));
        assert_eq!(of_blocker(class).unwrap().kind, Kind::Deny);
    }
}

// P41, §9.6.1
#[test]
fn p41_reason_user_is_a_closed_word_and_reason_admin_the_audit_scope() {
    for (i, r) in REASONS.iter().enumerate() {
        assert!(
            r.user.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
            "{}",
            r.user
        );
        assert!(REASONS.iter().skip(i + 1).all(|o| o.user != r.user));
        assert!(r.admin.contains(&AdminDetail::StateBasis), "{}", r.category);
        assert_eq!(r.kind == Kind::Require, r.proof.is_some(), "{}", r.category);
        assert_eq!(r.kind == Kind::Deny, r.blocker.is_some(), "{}", r.category);
    }
    for proof in ["contribution", "authentication", "claim", "selection"] {
        assert_eq!(of_requirement(proof).unwrap().kind, Kind::Require);
    }
    assert!(of_requirement("anything").is_none());
}
