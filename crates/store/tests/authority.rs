//! OP-130, OP-17, TI-2, TI-8: the authority log tables against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::StoreError;
use access_store::authority::{
    CommitBatch, Draw, HeadRow, LogRecord, NonceRow, OutboxRow, ProofRow, acquire_lease,
    commit_batch, counter, create_domain, domain_tenant, find_nonce, read_head, read_log,
    release_lease, renew_lease, versions,
};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};
use sqlx::{Executor, Row};

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const TTL: Duration = Duration::from_secs(10);

fn genesis(seed: u8) -> (DomainId, LogRecord) {
    let leaf = [seed; 32];
    (
        DomainId::from_bytes([seed.wrapping_add(1); 32]),
        LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 1_000,
            leaf_hash: leaf,
            envelope: vec![0xa0],
        },
    )
}

fn record(pos: u64, seed: u8) -> LogRecord {
    LogRecord {
        pos,
        kind: "decision",
        recorded_at: 2_000,
        leaf_hash: [seed; 32],
        envelope: vec![0xa1, seed],
    }
}

fn batch(epoch: u64, after: &HeadRow, seed: u8) -> CommitBatch {
    let pos = after.pos + 1;
    CommitBatch {
        epoch,
        after: after.pos,
        records: vec![record(pos, seed)],
        head: HeadRow {
            pos,
            epoch,
            leaf_hash: [seed; 32],
            recorded_at: 2_000,
            frontier: vec![[seed; 32]],
        },
        nonces: vec![NonceRow {
            outcome: String::from("allow"),
            nonce: vec![seed; 16],
            actor: vec![1],
            intent_digest: [9; 32],
            decision_pos: pos,
        }],
        outbox: vec![OutboxRow {
            pos,
            idx: 0,
            event_id: [seed; 32],
            event: vec![0xa0],
        }],
        proofs: vec![ProofRow {
            digest: [seed; 32],
            bytes: vec![1, 2, 3],
        }],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        effects: vec![],
    }
}

async fn domain(db: &TestDb, seed: u8) -> DomainId {
    let (d, g) = genesis(seed);
    create_domain(&db.sequencer, &d, TENANT, &g, &[])
        .await
        .unwrap();
    d
}

#[tokio::test]
async fn genesis_lease_and_commit() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 1).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    assert_eq!((lease.epoch, head.pos, head.epoch), (1, 0, 1));
    commit_batch(&db.sequencer, &d, TENANT, &batch(lease.epoch, &head, 2))
        .await
        .unwrap();
    let head = read_head(&db.app, &d).await.unwrap();
    assert_eq!(head.pos, 1);
    let log = read_log(&db.app, &d, 0, 10).await.unwrap();
    assert_eq!(log.iter().map(|r| r.pos).collect::<Vec<_>>(), [0, 1]);
    let n = find_nonce(&db.app, &d, &[2; 16]).await.unwrap().unwrap();
    assert_eq!(n.decision_pos, 1);
    renew_lease(&db.sequencer, &d, "a", lease, TTL)
        .await
        .unwrap();
    release_lease(&db.sequencer, &d, "a", lease).await.unwrap();
}

// OP-12 m.1, OP-141 m.18 (a)
#[tokio::test]
async fn a_domain_names_its_tenant() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 9).await;
    assert_eq!(
        domain_tenant(&db.sequencer, &d).await.unwrap(),
        Some(TENANT)
    );
    let (unknown, _) = genesis(10);
    assert_eq!(domain_tenant(&db.sequencer, &unknown).await.unwrap(), None);
}

#[tokio::test]
async fn new_leader_fences_the_old_one() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 3).await;
    let (old, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    assert!(matches!(
        acquire_lease(&db.sequencer, &d, "b", TTL).await,
        Err(StoreError::LeaseHeld)
    ));
    release_lease(&db.sequencer, &d, "a", old).await.unwrap();
    let (new, _) = acquire_lease(&db.sequencer, &d, "b", TTL).await.unwrap();
    assert!(new.epoch > old.epoch);
    // TI-2: the old leader's write fails even though its in-memory head is current
    let stale = commit_batch(&db.sequencer, &d, TENANT, &batch(old.epoch, &head, 4)).await;
    assert!(matches!(stale, Err(StoreError::HeadMoved)));
    assert!(matches!(
        renew_lease(&db.sequencer, &d, "a", old, TTL).await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(read_head(&db.app, &d).await.unwrap().pos, 0);
    commit_batch(&db.sequencer, &d, TENANT, &batch(new.epoch, &head, 5))
        .await
        .unwrap();
}

#[tokio::test]
async fn racing_batches_commit_once() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 6).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let (x, y) = (batch(lease.epoch, &head, 7), batch(lease.epoch, &head, 8));
    let (a, b) = tokio::join!(
        commit_batch(&db.sequencer, &d, TENANT, &x),
        commit_batch(&db.sequencer, &d, TENANT, &y),
    );
    assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
    assert_eq!(read_log(&db.app, &d, 0, 10).await.unwrap().len(), 2);
}

// TI-7
#[tokio::test]
async fn failed_batch_leaves_nothing_behind() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 9).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let mut bad = batch(lease.epoch, &head, 10);
    bad.nonces[0].decision_pos = 99;
    assert!(commit_batch(&db.sequencer, &d, TENANT, &bad).await.is_err());
    assert_eq!(read_head(&db.app, &d).await.unwrap().pos, 0);
    assert!(find_nonce(&db.app, &d, &[10; 16]).await.unwrap().is_none());
    commit_batch(&db.sequencer, &d, TENANT, &batch(lease.epoch, &head, 10))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_nonce_is_consumed_once() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 11).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    commit_batch(&db.sequencer, &d, TENANT, &batch(lease.epoch, &head, 12))
        .await
        .unwrap();
    let head = read_head(&db.app, &d).await.unwrap();
    let mut again = batch(lease.epoch, &head, 13);
    again.nonces[0].nonce = vec![12; 16];
    assert!(
        commit_batch(&db.sequencer, &d, TENANT, &again)
            .await
            .is_err()
    );
}

// OP-141 m.9, L2-REC-5: require_action leaves a nonce open for the same intent and actor;
// allow and deny close it
#[tokio::test]
async fn a_nonce_stays_open_only_after_require_action() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 16).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let mut first = batch(lease.epoch, &head, 17);
    first.nonces[0].outcome = String::from("require_action");
    commit_batch(&db.sequencer, &d, TENANT, &first)
        .await
        .unwrap();
    let nonce = first.nonces[0].nonce.clone();
    let head = read_head(&db.app, &d).await.unwrap();
    let mut other_intent = batch(lease.epoch, &head, 18);
    other_intent.nonces[0].nonce.clone_from(&nonce);
    other_intent.nonces[0].intent_digest = [8; 32];
    assert!(
        commit_batch(&db.sequencer, &d, TENANT, &other_intent)
            .await
            .is_err()
    );
    let mut allow = batch(lease.epoch, &head, 18);
    allow.nonces[0] = NonceRow {
        decision_pos: allow.records[0].pos,
        outcome: String::from("allow"),
        ..first.nonces[0].clone()
    };
    commit_batch(&db.sequencer, &d, TENANT, &allow)
        .await
        .unwrap();
    let latest = find_nonce(&db.app, &d, &nonce).await.unwrap().unwrap();
    assert_eq!(latest.outcome, "allow");
    let head = read_head(&db.app, &d).await.unwrap();
    let mut after = batch(lease.epoch, &head, 19);
    after.nonces[0] = NonceRow {
        decision_pos: after.records[0].pos,
        outcome: String::from("require_action"),
        ..first.nonces[0].clone()
    };
    assert!(
        commit_batch(&db.sequencer, &d, TENANT, &after)
            .await
            .is_err()
    );
}

// INV-30, G23
#[tokio::test]
async fn append_only_tables_reject_change_at_every_layer() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 14).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    commit_batch(&db.sequencer, &d, TENANT, &batch(lease.epoch, &head, 15))
        .await
        .unwrap();
    let scope = format!(
        "SELECT set_config('app.domain_id', '{}', true)",
        hex(d.as_bytes())
    );
    for table in [
        "authority_log",
        "authority_nonce",
        "authority_outbox",
        "proof_store",
    ] {
        // OP-17 layer 1: the roles hold no UPDATE, DELETE or TRUNCATE
        for pool in [&db.app, &db.sequencer] {
            for stmt in [
                format!("UPDATE access.{table} SET domain_id = domain_id"),
                format!("DELETE FROM access.{table}"),
                format!("TRUNCATE access.{table}"),
            ] {
                let mut tx = pool.begin().await.unwrap();
                tx.execute(sqlx::AssertSqlSafe(scope.clone()))
                    .await
                    .unwrap();
                let err = tx
                    .execute(sqlx::AssertSqlSafe(stmt.clone()))
                    .await
                    .unwrap_err();
                assert!(
                    err.to_string().contains("permission denied"),
                    "{table}: {stmt}: {err}"
                );
            }
        }
        // OP-17 layers 2 and 3: even the owner is stopped by the triggers
        for stmt in [
            format!("UPDATE access.{table} SET domain_id = domain_id"),
            format!("DELETE FROM access.{table}"),
            format!("TRUNCATE access.{table} CASCADE"),
        ] {
            let mut tx = db.owner.begin().await.unwrap();
            tx.execute("SET LOCAL ROLE access_migrator").await.unwrap();
            tx.execute(sqlx::AssertSqlSafe(scope.clone()))
                .await
                .unwrap();
            let err = tx
                .execute(sqlx::AssertSqlSafe(stmt.clone()))
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("append-only"),
                "{table}: {stmt}: {err}"
            );
        }
    }
}

// INV-2
#[tokio::test]
async fn only_the_sequencer_writes_the_log() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 16).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let err = commit_batch(&db.app, &d, TENANT, &batch(lease.epoch, &head, 17))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

// U59
#[tokio::test]
async fn unscoped_and_cross_domain_reads_see_nothing() {
    let db = fresh().await.unwrap();
    let a = domain(&db, 18).await;
    let b = domain(&db, 20).await;
    // §12.1.3 test 6: no scope, no rows
    for table in [
        "authority_domain",
        "authority_log",
        "domain_head",
        "authority_nonce",
        "authority_outbox",
        "proof_store",
    ] {
        let n: i64 = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM access.{table}"
        )))
        .fetch_one(&db.app)
        .await
        .unwrap()
        .get(0);
        assert_eq!(n, 0, "{table}");
    }
    assert_eq!(read_log(&db.app, &a, 0, 10).await.unwrap().len(), 1);
    let mut tx = db.app.begin().await.unwrap();
    tx.execute(sqlx::AssertSqlSafe(format!(
        "SELECT set_config('app.domain_id', '{}', true)",
        hex(a.as_bytes())
    )))
    .await
    .unwrap();
    let rows: i64 = sqlx::query("SELECT count(*) FROM access.authority_log WHERE domain_id = $1")
        .bind(b.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0);
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

// TI-4, §17.1.1 step 9: a key read before the batch must still have that version
#[tokio::test]
async fn a_changed_read_refuses_the_batch_and_writes_nothing() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 30).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let mut first = batch(lease.epoch, &head, 31);
    first.writes = vec![(b"grants@p1".to_vec(), 1)];
    commit_batch(&db.sequencer, &d, TENANT, &first)
        .await
        .unwrap();
    assert_eq!(
        versions(&db.app, &d, &[b"grants@p1".to_vec(), b"absent".to_vec()])
            .await
            .unwrap(),
        [1, 0]
    );
    let head = read_head(&db.app, &d).await.unwrap();
    let mut stale = batch(lease.epoch, &head, 32);
    stale.reads = vec![(b"grants@p1".to_vec(), 0)];
    assert!(matches!(
        commit_batch(&db.sequencer, &d, TENANT, &stale).await,
        Err(StoreError::Stale)
    ));
    // a negative read of a collection key is caught the same way
    let mut negative = batch(lease.epoch, &head, 33);
    negative.reads = vec![(b"absent".to_vec(), 0), (b"grants@p1".to_vec(), 1)];
    negative.writes = vec![(b"absent".to_vec(), 2)];
    commit_batch(&db.sequencer, &d, TENANT, &negative)
        .await
        .unwrap();
    let head = read_head(&db.app, &d).await.unwrap();
    let mut late = batch(lease.epoch, &head, 34);
    late.reads = vec![(b"absent".to_vec(), 0)];
    assert!(matches!(
        commit_batch(&db.sequencer, &d, TENANT, &late).await,
        Err(StoreError::Stale)
    ));
    assert_eq!(read_head(&db.app, &d).await.unwrap().pos, 2);
    assert!(find_nonce(&db.app, &d, &[34; 16]).await.unwrap().is_none());
}

// §17.1.1 step 9: a draw never takes a counter past the limit the evaluation saw
#[tokio::test]
async fn draws_stop_at_the_limit() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 35).await;
    let (lease, _) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    for (seed, draw, ok) in [(36, 6, true), (37, 4, true), (38, 1, false)] {
        let head = read_head(&db.app, &d).await.unwrap();
        let mut b = batch(lease.epoch, &head, seed);
        b.draws = vec![Draw {
            key: b"budget@n1".to_vec(),
            limit: 10,
            draw,
        }];
        let r = commit_batch(&db.sequencer, &d, TENANT, &b).await;
        assert_eq!(r.is_ok(), ok, "{seed}: {r:?}");
        if !ok {
            assert!(matches!(r, Err(StoreError::Exhausted)));
        }
    }
    assert_eq!(counter(&db.app, &d, b"budget@n1").await.unwrap(), 10);
    let head = read_head(&db.app, &d).await.unwrap();
    let mut over = batch(lease.epoch, &head, 39);
    over.draws = vec![Draw {
        key: b"budget@n2".to_vec(),
        limit: 3,
        draw: 4,
    }];
    assert!(matches!(
        commit_batch(&db.sequencer, &d, TENANT, &over).await,
        Err(StoreError::Exhausted)
    ));
}

// G56: a draw that would overflow the counter or does not fit the column commits nothing
#[tokio::test]
async fn an_overflowing_draw_commits_nothing() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 44).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let mut b = batch(lease.epoch, &head, 45);
    b.draws = vec![Draw {
        key: b"budget@big".to_vec(),
        limit: i64::MAX.unsigned_abs(),
        draw: 10,
    }];
    commit_batch(&db.sequencer, &d, TENANT, &b).await.unwrap();
    for (seed, draw, limit) in [
        (46, i64::MAX.unsigned_abs() - 5, i64::MAX.unsigned_abs()),
        (47, u64::MAX, u64::MAX),
    ] {
        let head = read_head(&db.app, &d).await.unwrap();
        let mut over = batch(lease.epoch, &head, seed);
        over.draws = vec![Draw {
            key: b"budget@big".to_vec(),
            limit,
            draw,
        }];
        assert!(
            commit_batch(&db.sequencer, &d, TENANT, &over)
                .await
                .is_err()
        );
        assert_eq!(read_head(&db.app, &d).await.unwrap().pos, head.pos);
    }
    assert_eq!(counter(&db.app, &d, b"budget@big").await.unwrap(), 10);
}

// INV-20: a single-use flag is set once
#[tokio::test]
async fn single_use_flags_are_set_once() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 40).await;
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    let mut b = batch(lease.epoch, &head, 41);
    b.single_use = vec![(b"contrib@x".to_vec(), 1)];
    commit_batch(&db.sequencer, &d, TENANT, &b).await.unwrap();
    let head = read_head(&db.app, &d).await.unwrap();
    let mut again = batch(lease.epoch, &head, 42);
    again.single_use = vec![(b"contrib@x".to_vec(), 2)];
    assert!(matches!(
        commit_batch(&db.sequencer, &d, TENANT, &again).await,
        Err(StoreError::Consumed)
    ));
}

// OP-73, OP-135: even the owner can only rewrap or shred a body, and shred it once
#[tokio::test]
async fn body_rows_allow_only_rewrap_and_one_shred() {
    use access_store::bodies::{put, shred};
    let db = fresh().await.unwrap();
    let d = domain(&db, 50).await;
    put(
        &db.sequencer,
        &d,
        &[1; 32],
        "k1",
        &[0; 40],
        &[0; 12],
        &[0; 16],
    )
    .await
    .unwrap();
    let scope = format!(
        "SELECT set_config('app.domain_id', '{}', true)",
        hex(d.as_bytes())
    );
    let attempt = |stmt: &'static str| {
        let scope = scope.clone();
        let owner = db.owner.clone();
        async move {
            let mut tx = owner.begin().await.unwrap();
            tx.execute("SET LOCAL ROLE access_migrator").await.unwrap();
            tx.execute(sqlx::AssertSqlSafe(scope)).await.unwrap();
            tx.execute(stmt).await.map(|_| ())
        }
    };
    for stmt in [
        "UPDATE access.body_store SET ciphertext = '\\x01'",
        "UPDATE access.body_store SET body_commit = '\\x0202020202020202020202020202020202020202020202020202020202020202'",
        "UPDATE access.body_store SET shredded_at = now()",
        "DELETE FROM access.body_store",
        "TRUNCATE access.body_store",
    ] {
        assert!(attempt(stmt).await.is_err(), "{stmt}");
    }
    assert!(
        attempt("UPDATE access.body_store SET kek_id = 'k2', wrapped_dek = '\\x01'")
            .await
            .is_ok()
    );
    shred(&db.sequencer, &d, &[1; 32]).await.unwrap();
    assert!(
        attempt("UPDATE access.body_store SET kek_id = 'k3'")
            .await
            .is_err(),
        "a shredded row never changes"
    );
}
