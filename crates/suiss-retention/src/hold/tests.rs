use alloc::format;
use alloc::vec;

use super::{Hold, HoldKind, HoldScope};
use crate::class::Class;
use crate::decision::{Occurrence, Record};
use crate::ids::{HoldId, SubjectId, TenantId};
use crate::time::Timestamp;

fn hold(scope: HoldScope) -> Hold {
    Hold {
        id: HoldId::new("h1"),
        tenant: TenantId::new("t1"),
        scope,
        placed_at: Timestamp::from_unix_millis(1_000),
        until: None,
        kind: HoldKind::Litigation,
        suspicious_activity: false,
    }
}

fn record(tenant: &str, class: Class, subject: Option<&str>) -> Record {
    Record {
        tenant: TenantId::new(tenant),
        class,
        subject: subject.map(SubjectId::new),
        start: Occurrence::Unknown,
        end: Occurrence::Unknown,
    }
}

// OP-74 m.3, OP-147 m.2
#[test]
fn scope_decides_what_a_hold_covers() {
    let subject = hold(HoldScope::Subject(SubjectId::new("s1")));
    assert!(subject.covers(&record("t1", Class::Kyc, Some("s1"))));
    assert!(subject.covers(&record("t1", Class::WorkRecord, Some("s1"))));
    assert!(!subject.covers(&record("t1", Class::Kyc, Some("s2"))));
    assert!(!subject.covers(&record("t1", Class::Kyc, None)));
    assert!(!subject.covers(&record("t2", Class::Kyc, Some("s1"))));

    let classes = hold(HoldScope::Classes(vec![Class::Kyc, Class::Transaction]));
    assert!(classes.covers(&record("t1", Class::Transaction, Some("s9"))));
    assert!(classes.covers(&record("t1", Class::Kyc, None)));
    assert!(!classes.covers(&record("t1", Class::Audit, Some("s9"))));

    let tenant = hold(HoldScope::Tenant);
    assert!(tenant.covers(&record("t1", Class::WorkDraft, None)));
    assert!(!tenant.covers(&record("t2", Class::WorkDraft, None)));
}

// OP-74 m.3
#[test]
fn a_hold_is_active_until_its_end() {
    let mut h = hold(HoldScope::Tenant);
    assert!(h.is_active(Timestamp::from_unix_millis(0)));
    assert!(h.is_active(Timestamp::from_unix_millis(u64::MAX)));
    h.until = Some(Timestamp::from_unix_millis(5_000));
    assert!(h.is_active(Timestamp::from_unix_millis(4_999)));
    assert!(!h.is_active(Timestamp::from_unix_millis(5_000)));
}

// OP-74 m.4, Ek C.1.1
#[test]
fn suspicious_activity_scope_is_not_printed() {
    let mut h = hold(HoldScope::Subject(SubjectId::new("subject-42")));
    assert!(format!("{h:?}").contains("subject-42"));
    h.suspicious_activity = true;
    let shown = format!("{h:?}");
    assert!(!shown.contains("subject-42"));
    assert!(shown.contains("<confidential>"));
}

// OP-147 m.4
#[cfg(feature = "serde")]
#[test]
fn hold_wire_form() {
    let mut h = hold(HoldScope::Classes(vec![Class::AmlReport]));
    h.kind = HoldKind::LawEnforcement;
    h.until = Some(Timestamp::from_unix_millis(9_000));
    let json = serde_json::to_value(&h).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "id": "h1",
            "tenant": "t1",
            "scope": {"classes": ["aml_report"]},
            "placed_at": 1000,
            "until": 9000,
            "kind": "law_enforcement",
            "suspicious_activity": false,
        })
    );
    assert_eq!(serde_json::from_value::<Hold>(json).unwrap(), h);
    let tenant = serde_json::to_value(hold(HoldScope::Tenant)).unwrap();
    assert_eq!(tenant["scope"], "tenant");
}
