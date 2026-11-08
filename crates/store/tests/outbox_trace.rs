//! OP-67 m.1: an outbox row carries the writing request's traceparent to its consumer; the
//! column takes only a well-formed version-00 value.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::{Duration, Instant};

use access_store::identity::{Cursor, RealmId, TenantId, TenantTx, poll};
use access_store::testing::fresh;

const T: TenantId = TenantId::from_bytes([1; 16]);
const R: RealmId = RealmId::from_bytes([2; 16]);
const TP: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

// OP-67 m.1, §17.8.2
#[tokio::test]
async fn the_outbox_carries_the_trace() {
    let db = fresh().await.unwrap();
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    t.outbox_traced("session.revoked", b"traced", Some(TP))
        .await
        .unwrap();
    t.outbox("session.revoked", b"plain").await.unwrap();
    t.commit().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut rows = poll(&db.reader, Cursor::default(), 10).await.unwrap();
    while rows.len() < 2 {
        assert!(Instant::now() < deadline, "rows not visible after 20 s");
        tokio::time::sleep(Duration::from_millis(20)).await;
        rows = poll(&db.reader, Cursor::default(), 10).await.unwrap();
    }
    let traces: Vec<(Vec<u8>, Option<String>)> = rows
        .iter()
        .map(|e| (e.payload.clone(), e.trace_parent.clone()))
        .collect();
    assert_eq!(
        traces,
        vec![
            (b"traced".to_vec(), Some(TP.to_owned())),
            (b"plain".to_vec(), None)
        ]
    );
    assert!(rows.iter().all(|e| e.age_ms < 60_000));
}

// OP-67 m.1
#[tokio::test]
async fn a_malformed_trace_is_refused() {
    let db = fresh().await.unwrap();
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    assert!(
        t.outbox_traced("session.revoked", b"x", Some("00-zz"))
            .await
            .is_err()
    );
}
