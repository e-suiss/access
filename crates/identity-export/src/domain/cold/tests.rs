#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use access_identity_audit::domain::tier::root;

use super::*;

fn row(id: i64, event: &str) -> AuditRow {
    AuditRow {
        tenant: [0x11; 16],
        realm: [0x22; 16],
        at_ms: 1_767_225_600_000,
        id,
        xid: 900 + u64::try_from(id).unwrap(),
        event_type: event.to_owned(),
        actor: String::from("user:0193"),
        target: String::from("session:abc"),
        correlation: String::from("req-1"),
    }
}

// OP-40, OP-41, OP-158 m.3 (w)
#[test]
fn the_cold_file_gives_back_every_row_and_so_the_partition_root() {
    let rows = vec![
        row(1, "session.created"),
        row(2, "session.signed_out"),
        row(3, "session.created"),
    ];
    let file = ColdParquet.encode(&rows).unwrap();
    let back = ColdParquet.decode(&file).unwrap();
    assert_eq!(back, rows);
    assert_eq!(root(&back).unwrap(), root(&rows).unwrap());
    assert_eq!(ColdParquet.encode(&rows).unwrap(), file);
    let text = crate::testing::parquet_rows(&file).unwrap();
    assert!(text[0].contains("class_uid"), "{}", text[0]);
    assert!(ColdParquet.decode(b"not parquet").is_err());
    assert_eq!(
        ColdParquet
            .decode(&ColdParquet.encode(&[]).unwrap())
            .unwrap(),
        vec![]
    );
}
