//! OQ-MD3 scenarios for candidate A, the xid8 watermark (OP-20, OPI-1): every event written is
//! delivered, in a stable order, whatever the commit order, transaction length or consumer
//! history. Failover is exercised by `just oq-md3` against a streaming replica.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::{Duration, Instant};

use access_store::identity::{Cursor, OutboxEvent, RealmId, TenantId, TenantTx, ack, cursor, poll};
use access_store::testing::{TestDb, fresh};
use sqlx::{Executor, PgPool, Row};

const T: TenantId = TenantId::from_bytes([1; 16]);
const R: RealmId = RealmId::from_bytes([2; 16]);

async fn write(db: &TestDb, payload: &[u8]) {
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    t.outbox("session.revoked", payload).await.unwrap();
    t.commit().await.unwrap();
}

/// Drains everything currently deliverable, acknowledging as it goes.
async fn drain(reader: &PgPool, consumer: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let at = cursor(reader, consumer).await.unwrap();
        let batch: Vec<OutboxEvent> = poll(reader, at, 100).await.unwrap();
        let Some(last) = batch.last().map(OutboxEvent::cursor) else {
            return out;
        };
        out.extend(batch.into_iter().map(|e| e.payload));
        ack(reader, consumer, last).await.unwrap();
    }
}

/// Drains until `n` events arrived. The watermark is cluster-wide, so a writing transaction
/// in another test's database delays delivery (never loses it); the deadline bounds that wait.
async fn drain_n(reader: &PgPool, consumer: &str, n: usize) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut out = drain(reader, consumer).await;
    while out.len() < n {
        assert!(
            Instant::now() < deadline,
            "{} of {n} events after 20 s",
            out.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        out.extend(drain(reader, consumer).await);
    }
    out
}

// OQ-MD3 scenario 1: reverse commit order (the gap trap)
#[tokio::test]
async fn an_earlier_transaction_that_commits_later_is_not_skipped() {
    let db = fresh().await.unwrap();
    let mut early = TenantTx::begin(&db.app, T, R).await.unwrap();
    early.outbox("session.revoked", b"early").await.unwrap();
    write(&db, b"late").await;

    assert!(
        drain(&db.reader, "a").await.is_empty(),
        "nothing is delivered past a running transaction"
    );
    // a naive `id > last` cursor would read `late` now and then pass over `early`'s lower id
    let visible: Vec<i64> = sqlx::query("SELECT id FROM access.identity_outbox ORDER BY id")
        .fetch_all(&db.reader)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(visible.len(), 1);

    early.commit().await.unwrap();
    assert_eq!(
        drain_n(&db.reader, "a", 2).await,
        [b"early".to_vec(), b"late".to_vec()]
    );
}

// OQ-MD3 scenario 2: a long transaction holds delivery back; an aborted one never appears
#[tokio::test]
async fn long_and_aborted_transactions() {
    let db = fresh().await.unwrap();
    let mut long = TenantTx::begin(&db.app, T, R).await.unwrap();
    long.outbox("session.revoked", b"long").await.unwrap();
    for i in 0..50_u8 {
        write(&db, &[i]).await;
    }
    assert_eq!(drain(&db.reader, "a").await, Vec::<Vec<u8>>::new());
    let mut aborted = TenantTx::begin(&db.app, T, R).await.unwrap();
    aborted.outbox("session.revoked", b"aborted").await.unwrap();
    aborted.rollback().await.unwrap();
    long.commit().await.unwrap();
    let got = drain_n(&db.reader, "a", 51).await;
    assert_eq!(got.len(), 51);
    assert_eq!(got[0], b"long");
    assert!(!got.contains(&b"aborted".to_vec()));
}

// OQ-MD3 scenario 2: a rolled-back savepoint drops only its own event
#[tokio::test]
async fn savepoints_keep_the_top_level_transaction_id() {
    let db = fresh().await.unwrap();
    let mut c = db.app.acquire().await.unwrap();
    c.execute("BEGIN").await.unwrap();
    c.execute("SELECT set_config('app.tenant_id', '01010101-0101-0101-0101-010101010101', true)")
        .await
        .unwrap();
    let ins = "INSERT INTO access.identity_outbox (tenant_id, realm_id, kind, payload) VALUES \
               ('01010101-0101-0101-0101-010101010101', '02020202-0202-0202-0202-020202020202', 'k', ";
    for (stmt, payload) in [
        ("", Some("01")),
        ("SAVEPOINT s", Some("02")),
        ("ROLLBACK TO SAVEPOINT s", None),
        ("SAVEPOINT u", Some("03")),
        ("RELEASE SAVEPOINT u", None),
    ] {
        if !stmt.is_empty() {
            c.execute(stmt).await.unwrap();
        }
        if let Some(p) = payload {
            c.execute(sqlx::AssertSqlSafe(format!("{ins}'\\x{p}')")))
                .await
                .unwrap();
        }
    }
    c.execute("COMMIT").await.unwrap();
    assert_eq!(drain_n(&db.reader, "a", 2).await, [vec![1], vec![3]]);
}

// OQ-MD3 scenario 3: a consumer away for longer than any retention still gets everything,
// because outbox rows are never deleted (OP-73)
#[tokio::test]
async fn a_long_outage_loses_nothing() {
    let db = fresh().await.unwrap();
    write(&db, b"before").await;
    assert_eq!(drain_n(&db.reader, "a", 1).await.len(), 1);
    for chunk in 0..20_u8 {
        let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
        for i in 0..50_u8 {
            t.outbox("session.revoked", &[chunk, i]).await.unwrap();
        }
        t.commit().await.unwrap();
    }
    let got = drain_n(&db.reader, "a", 1000).await;
    assert_eq!(got.len(), 1000);
    assert_eq!(got.first().unwrap(), &vec![0, 0]);
    assert_eq!(got.last().unwrap(), &vec![19, 49]);
}

// OQ-MD3 scenario 4: a restart resumes from the stored cursor; delivery is at least once
#[tokio::test]
async fn restart_resumes_from_the_last_ack() {
    let db = fresh().await.unwrap();
    for i in 0..10_u8 {
        write(&db, &[i]).await;
    }
    assert_eq!(drain_n(&db.reader, "probe", 10).await.len(), 10);
    let first = poll(&db.reader, Cursor::default(), 4).await.unwrap();
    ack(&db.reader, "a", first[2].cursor()).await.unwrap();
    // crash after handling 4 events but acknowledging only 3
    db.reader.close().await;
    let reader = PgPool::connect_with(
        db.admin
            .clone()
            .username("access_test_reader")
            .password("test-only-not-a-secret"),
    )
    .await
    .unwrap();
    let rest = drain(&reader, "a").await;
    assert_eq!(rest, (3..10_u8).map(|i| vec![i]).collect::<Vec<_>>());
    // an ack never moves the cursor back
    ack(&reader, "a", first[0].cursor()).await.unwrap();
    assert_eq!(drain(&reader, "a").await, Vec::<Vec<u8>>::new());
}

// OQ-MD3 scenario 6: consumers keep independent cursors
#[tokio::test]
async fn consumers_are_independent() {
    let db = fresh().await.unwrap();
    for i in 0..30_u8 {
        write(&db, &[i]).await;
    }
    let (a, b) = tokio::join!(
        drain_n(&db.reader, "relay", 30),
        drain_n(&db.reader, "ssf", 30)
    );
    assert_eq!(a.len(), 30);
    assert_eq!(a, b);
    write(&db, b"more").await;
    assert_eq!(drain_n(&db.reader, "relay", 1).await, [b"more".to_vec()]);
    assert_eq!(drain_n(&db.reader, "ssf", 1).await, [b"more".to_vec()]);
}

// OP-12, OP-131 m.3: the application sees only its tenant; the reader cannot write
#[tokio::test]
async fn scope_and_roles() {
    let db = fresh().await.unwrap();
    write(&db, b"a").await;
    let other = TenantId::from_bytes([9; 16]);
    let mut t = TenantTx::begin(&db.app, other, R).await.unwrap();
    t.outbox("session.revoked", b"x").await.unwrap();
    t.rollback().await.unwrap();
    let seen: i64 = sqlx::query("SELECT count(*) FROM access.identity_outbox")
        .fetch_one(&db.app)
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "no scope, no rows");
    let err = sqlx::query(
        "INSERT INTO access.identity_outbox (tenant_id, realm_id, kind, payload) VALUES ($1, $1, 'k', '\\x00')",
    )
    .bind(sqlx::types::Uuid::from_bytes([1; 16]))
    .execute(&db.reader)
    .await
    .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}
