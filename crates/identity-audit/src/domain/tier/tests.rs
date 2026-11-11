#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

fn row(id: i64) -> AuditRow {
    AuditRow {
        tenant: [1; 16],
        realm: [2; 16],
        at_ms: 1_000,
        id,
        xid: 7,
        event_type: String::from("session.created"),
        actor: String::from("user:a"),
        target: String::from("session:s"),
        correlation: String::from("c1"),
    }
}

// OP-73 m.4, OP-158 m.3 (w)
#[test]
fn a_copy_is_its_partition_only_with_every_row_unchanged() {
    let rows = vec![row(1), row(2), row(3)];
    assert_eq!(check_copy(&rows, &rows).unwrap(), root(&rows).unwrap());
    let mut changed = rows.clone();
    changed[1].actor = String::from("user:b");
    assert!(matches!(
        check_copy(&rows, &changed),
        Err(AuditError::ColdMismatch)
    ));
    assert!(matches!(
        check_copy(&rows, &rows[..2]),
        Err(AuditError::ColdMismatch)
    ));
    let mut reordered = rows.clone();
    reordered.swap(0, 2);
    assert!(matches!(
        check_copy(&rows, &reordered),
        Err(AuditError::ColdMismatch)
    ));
    assert_eq!(
        object_key("identity_audit_202601_default", (2026, 1)),
        "identity-audit/2026/01/identity_audit_202601_default.parquet"
    );
}
