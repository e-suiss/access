//! OP-156 m.3 (s), OP-41, OP-73, X22: export sinks and cursors on real Postgres. A sink version is
//! written only under a committed `idp.export.*` ALLOW and is fixed; a newer version shreds the
//! older secret; the cursor only moves forward and only from where it is; nothing is deleted.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::audit::AuditEvent;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::events::SealedKey;
use access_store::export::{
    NewSink, advance, audit_after, cursor, failed, notified, sink, sinks, write,
};
use access_store::identity::{Cursor, RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind, create_settings};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

const TTL: Duration = Duration::from_secs(10);
const INTENT: [u8; 32] = [9; 32];

async fn domain(db: &TestDb, t: TenantId, seed: u8, allows: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    for i in 1..=allows {
        let pos = head.pos + 1;
        let leaf = [seed.wrapping_add(i); 32];
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, i],
            }],
            head: next.clone(),
            nonces: vec![NonceRow {
                nonce: vec![i; 16],
                actor: vec![1],
                intent_digest: INTENT,
                decision_pos: pos,
                outcome: String::from("allow"),
                render_digest: None,
                tier: None,
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

async fn realm(db: &TestDb, t: TenantId, d: &DomainId) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, "acme", "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    r
}

fn decision<'a>(d: &'a DomainId, position: u64, nonce: &'a [u8], action: &'a str) -> Decision<'a> {
    Decision {
        domain: d,
        position,
        nonce,
        intent: INTENT,
        change: [5; 32],
        action,
    }
}

fn sealed(fill: u8) -> SealedKey {
    SealedKey {
        kek_id: String::from("kek-1"),
        wrapped_dek: vec![fill; 40],
        nonce: [fill; 12],
        ciphertext: vec![fill; 24],
    }
}

fn spec<'a>(state: &'a str, secret: Option<&'a SealedKey>) -> NewSink<'a> {
    NewSink {
        id: [4; 16],
        name: "splunk",
        state,
        adapter: "collector",
        preset: Some("splunk"),
        format: None,
        endpoint: "https://hec.example/services/collector/event",
        settings: "{\"index\":\"main\"}",
        secret,
    }
}

/// The rows after `after` once `n` of them have settled: rows of transactions that ended before
/// every transaction still open in the cluster.
async fn settled(tx: &mut TenantTx, after: Cursor, n: usize) -> Vec<access_store::audit::AuditRow> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let rows = audit_after(tx, after, 100).await.unwrap();
        if rows.len() >= n || std::time::Instant::now() > deadline {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// OP-156 m.3 (s), OP-73, X22
#[tokio::test]
async fn sinks_follow_decisions_and_cursors_only_move_forward() {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, tenant, 41, 3).await;
    let r = realm(&db, tenant, &d).await;

    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    let unbound = bind(
        &mut tx,
        &decision(&d, 1, &[1; 16], "idp.export.sink_register"),
    )
    .await
    .unwrap()
    .unwrap();
    let first = sealed(1);
    assert_eq!(
        write(&mut tx, &unbound, &spec("live", Some(&first)))
            .await
            .unwrap(),
        1
    );
    for i in 0..3 {
        tx.audit(&AuditEvent {
            event_type: "login.password.succeeded",
            actor: "a",
            target: &format!("t{i}"),
            correlation: "-",
        })
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    let update = bind(
        &mut tx,
        &decision(&d, 2, &[2; 16], "idp.export.sink_update"),
    )
    .await
    .unwrap()
    .unwrap();
    let second = sealed(2);
    assert_eq!(
        write(&mut tx, &update, &spec("live", Some(&second)))
            .await
            .unwrap(),
        2
    );
    let s = sink(&mut tx, "splunk").await.unwrap().unwrap();
    assert_eq!((s.version, s.state.as_str()), (2, "live"));
    assert_eq!(s.secret, Some(second));
    assert_eq!(s.settings, "{\"index\": \"main\"}");
    assert_eq!(sinks(&mut tx).await.unwrap().len(), 1);

    // OP-44
    let start = cursor(&mut tx, [4; 16]).await.unwrap().unwrap();
    assert_eq!((start.after, start.sent), (Cursor { xid: 0, id: 0 }, 0));
    let rows = settled(&mut tx, start.after, 3).await;
    let mid = Cursor {
        xid: rows[0].xid,
        id: rows[0].id,
    };
    // X22
    assert_eq!(failed(&mut tx, [4; 16], "status-503").await.unwrap(), 1);
    assert_eq!(failed(&mut tx, [4; 16], "status-503").await.unwrap(), 2);
    assert!(notified(&mut tx, [4; 16]).await.unwrap());
    assert!(!notified(&mut tx, [4; 16]).await.unwrap());
    let c = cursor(&mut tx, [4; 16]).await.unwrap().unwrap();
    assert_eq!((c.after, c.failures, c.notified), (start.after, 2, true));
    assert!(
        advance(&mut tx, [4; 16], (start.after, mid), 1)
            .await
            .unwrap()
    );
    assert!(
        !advance(&mut tx, [4; 16], (start.after, mid), 1)
            .await
            .unwrap()
    );
    let c = cursor(&mut tx, [4; 16]).await.unwrap().unwrap();
    assert_eq!(
        (c.after, c.sent, c.failures, c.notified),
        (mid, 1, 0, false)
    );
    assert_eq!(settled(&mut tx, mid, 2).await.len(), 2);

    let retire = bind(
        &mut tx,
        &decision(&d, 3, &[3; 16], "idp.export.sink_retire"),
    )
    .await
    .unwrap()
    .unwrap();
    write(&mut tx, &retire, &spec("retired", None))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // OP-73
    let left: Vec<(i64, bool)> = sqlx::query_as(
        "SELECT version, secret_sealed IS NOT NULL FROM access.export_sinks ORDER BY version",
    )
    .fetch_all(&db.owner)
    .await
    .unwrap();
    assert_eq!(left, [(1, false), (2, false), (3, false)]);
    for sql in [
        "UPDATE access.export_sinks SET endpoint = 'https://other.example/'",
        "UPDATE access.export_sinks SET secret_sealed = '\\x00'",
        "UPDATE access.export_cursors SET after_xid = 0, after_id = 0",
        "DELETE FROM access.export_sinks",
        "DELETE FROM access.export_cursors",
    ] {
        assert!(sqlx::query(sql).execute(&db.owner).await.is_err(), "{sql}");
    }
}
