//! Failover on a replicated cell (OP-24…OP-27, FA-1, SA-47, OP-158 m.3 (n)): `scripts/pg-ha.sh`
//! runs a primary and two synchronous standbys (`ANY 1 (sb_a, sb_b)`), and these tests really
//! SIGKILL, SIGSTOP and promote PostgreSQL processes, then assert on what was acknowledged before
//! the fault. They need the lane's cell (`ACCESS_PG_HA_PORT`, `ACCESS_PG_HA_DIR`) and run one at a
//! time in the `pg-ha` test group: `cargo nextest run -p access-store --run-ignored only -E
//! 'test(pg_ha)'`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::process::Command;
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use access_store::StoreError;
use access_store::authority::{
    CommitBatch, HeadRow, Lease, LogRecord, acquire_lease, commit_batch, create_domain, read_head,
    read_log,
};
use access_store::connect::{Durability, Failover, check_server, select_writable};
use access_store::replica_reads::{ReplicaReads, current_lsn};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, admin_text, attach_at, fresh_at};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/pg-ha.sh");
const PASSWORD: &str = "local-only-not-a-secret";
const TENANT: [u8; 16] = [0x37; 16];

/// An acknowledged record: its position and leaf hash.
type Acked = (u64, [u8; 32]);

fn base_port() -> u16 {
    std::env::var("ACCESS_PG_HA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55_440)
}

fn port(node: &str) -> u16 {
    base_port()
        + match node {
            "primary" => 0,
            "sb_a" => 1,
            "sb_b" => 2,
            _ => panic!("{node}"),
        }
}

fn url(node: &str) -> String {
    format!(
        "postgres://postgres:{PASSWORD}@127.0.0.1:{}/postgres",
        port(node)
    )
}

/// Runs `scripts/pg-ha.sh` with `args`, off the runtime and bounded.
async fn sh(args: &[&str]) -> String {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let shown = args.join(" ");
    let out = tokio::time::timeout(
        Duration::from_secs(240),
        tokio::task::spawn_blocking(move || Command::new("bash").arg(SCRIPT).args(&args).output()),
    )
    .await
    .unwrap_or_else(|_| panic!("pg-ha.sh {shown} did not finish"))
    .unwrap()
    .unwrap();
    assert!(
        out.status.success(),
        "pg-ha.sh {shown}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A fresh cell and a fresh migrated database on its primary.
async fn cell() -> TestDb {
    sh(&["up"]).await;
    fresh_at(&url("primary")).await.unwrap()
}

/// A synthetic domain committing records through the store's atomic batch (T7).
struct Log {
    id: DomainId,
    lease: Lease,
    pos: u64,
    leaf: [u8; 32],
    frontier: Vec<[u8; 32]>,
}

fn leaf(domain: &DomainId, pos: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, b) in domain
        .as_bytes()
        .iter()
        .chain(pos.to_be_bytes().iter())
        .enumerate()
    {
        h[i % 32] ^= b.rotate_left(u32::try_from(i % 7).unwrap());
    }
    h[31] ^= u8::try_from(pos % 251).unwrap();
    h
}

impl Log {
    async fn create(db: &TestDb, seed: u8) -> Self {
        let id = DomainId::from_bytes([seed; 32]);
        let genesis = leaf(&id, 0);
        create_domain(
            &db.sequencer,
            &id,
            TENANT,
            &LogRecord {
                pos: 0,
                kind: "genesis",
                recorded_at: 1,
                leaf_hash: genesis,
                envelope: vec![0xa0],
            },
            &[],
        )
        .await
        .unwrap();
        let (lease, _) = acquire_lease(&db.sequencer, &id, "w7", Duration::from_secs(1))
            .await
            .unwrap();
        Self {
            id,
            lease,
            pos: 0,
            leaf: genesis,
            frontier: vec![genesis],
        }
    }

    /// Commits the next record; its position and leaf once acknowledged.
    async fn push(&mut self, pool: &sqlx::PgPool) -> Result<(u64, [u8; 32]), StoreError> {
        let pos = self.pos + 1;
        let l = leaf(&self.id, pos);
        let batch = CommitBatch {
            epoch: self.lease.epoch,
            after: self.pos,
            records: vec![LogRecord {
                pos,
                kind: "claim",
                recorded_at: pos + 1,
                leaf_hash: l,
                envelope: vec![0xa1, 1],
            }],
            head: HeadRow {
                pos,
                epoch: self.lease.epoch,
                leaf_hash: l,
                recorded_at: pos + 1,
                frontier: vec![l],
            },
            nonces: vec![],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(pool, &self.id, TENANT, &batch).await?;
        self.pos = pos;
        self.leaf = l;
        self.frontier = vec![l];
        Ok((pos, l))
    }
}

// U32, FA-1, OP-24, Ek B 5990
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the replicated cell of scripts/pg-ha.sh (OP-158 m.3 (n))"]
async fn pg_ha_u32_every_acknowledged_record_survives_a_promote_after_sigkill() {
    let db = cell().await;
    let mut log = Log::create(&db, 0x41).await;
    let acked: Arc<Mutex<Vec<Acked>>> = Arc::default();
    let seen = acked.clone();
    let killer = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(60);
        while seen.lock().unwrap().len() < 40 {
            assert!(
                Instant::now() < deadline,
                "no 40 acknowledged commits in 60 s"
            );
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        sh(&["kill", "primary"]).await;
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match tokio::time::timeout(Duration::from_secs(10), log.push(&db.sequencer)).await {
            Ok(Ok(a)) => acked.lock().unwrap().push(a),
            Ok(Err(_)) | Err(_) => break,
        }
        assert!(
            Instant::now() < deadline,
            "the writer never saw the primary die"
        );
    }
    killer.await.unwrap();
    let acked = acked.lock().unwrap().clone();
    assert!(acked.len() >= 40);
    sh(&["promote", "sb_a"]).await;
    let promoted = attach_at(&url("sb_a"), &db.name).await.unwrap();
    let last = acked.last().unwrap().0;
    let records = read_log(&promoted.sequencer, &log.id, 1, last)
        .await
        .unwrap();
    for (pos, l) in &acked {
        let r = records
            .iter()
            .find(|r| r.pos == *pos)
            .unwrap_or_else(|| panic!("acknowledged record {pos} lost in the promote"));
        assert_eq!(&r.leaf_hash, l);
    }
    // TI-2
    let head = read_head(&promoted.sequencer, &log.id).await.unwrap();
    assert!(head.pos >= last);
    let lease = next_leader(&promoted, &log.id, "w7-next").await;
    assert!(lease.epoch > log.lease.epoch);
    sh(&["down"]).await;
}

/// The next leader on `db` once the old one's lease runs out (FA-7, TI-2).
async fn next_leader(db: &TestDb, id: &DomainId, holder: &str) -> Lease {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match acquire_lease(&db.sequencer, id, holder, Duration::from_secs(60)).await {
            Ok((lease, _)) => return lease,
            Err(StoreError::LeaseHeld) => {}
            Err(e) => panic!("{e}"),
        }
        assert!(Instant::now() < deadline, "the old lease never ran out");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn role_options(db: &TestDb, node: &str, user: &str, startup: &[(&str, &str)]) -> PgConnectOptions {
    PgConnectOptions::from_str(&url(node))
        .unwrap()
        .database(&db.name)
        .username(user)
        .password(access_store::testing::TEST_PASSWORD)
        .options(startup.iter().copied())
}

// OPI-4, OP-24, OP-54-RL6, Ek B 5989, 6093
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the replicated cell of scripts/pg-ha.sh (OP-158 m.3 (n))"]
async fn pg_ha_opi_4_one_standby_or_a_local_security_connection_is_refused() {
    let db = cell().await;
    let r = Durability::Replicated;
    check_server(&db.app, 8, false, r, None).await.unwrap();
    assert_eq!(
        admin_text(&db, "SELECT current_setting('synchronous_standby_names')")
            .await
            .unwrap()
            .as_deref(),
        Some("ANY 1 (sb_a, sb_b)")
    );
    sqlx::query(sqlx::AssertSqlSafe(String::from(
        "ALTER ROLE access_test_app SET synchronous_commit TO local",
    )))
    .execute(
        &mut <sqlx::PgConnection as sqlx::Connection>::connect_with(&db.admin)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let plain = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(role_options(&db, "primary", "access_test_app", &[]))
        .await
        .unwrap();
    let local = check_server(&plain, 8, false, r, None).await;
    assert!(
        matches!(&local, Err(StoreError::Unsafe(m)) if m.contains("synchronous_commit is local")),
        "{local:?}"
    );
    let store = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(role_options(
            &db,
            "primary",
            "access_test_app",
            &[("synchronous_commit", "on")],
        ))
        .await
        .unwrap();
    check_server(&store, 8, false, r, None).await.unwrap();
    sh(&[
        "sql",
        "primary",
        "ALTER SYSTEM SET synchronous_standby_names = 'ANY 1 (sb_a)'",
    ])
    .await;
    sh(&["sql", "primary", "SELECT pg_reload_conf()"]).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let one = check_server(&store, 8, false, r, None).await;
        if matches!(&one, Err(StoreError::Unsafe(m)) if m.contains("ANY k of at least two")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the one-standby quorum was accepted: {one:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sh(&["down"]).await;
}

// OP-26, OP-88, §16.7.1, Ek B 5996
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the replicated cell of scripts/pg-ha.sh (OP-158 m.3 (n))"]
async fn pg_ha_op_26_the_pool_follows_the_writable_host_and_evicts_the_old_one() {
    let db = cell().await;
    let base = role_options(
        &db,
        "primary",
        "access_test_sequencer",
        &[("synchronous_commit", "on")],
    );
    let hosts: Vec<String> = ["primary", "sb_a", "sb_b"]
        .iter()
        .map(|n| format!("127.0.0.1:{}", port(n)))
        .collect();
    assert_eq!(select_writable(&base, &hosts).await.unwrap(), hosts[0]);
    let f = Failover::open(base.clone(), hosts.clone(), 4)
        .await
        .unwrap();
    let mut log = Log::create(&db, 0x42).await;
    for _ in 0..5 {
        log.push(&f.pool()).await.unwrap();
    }
    sh(&["kill", "primary"]).await;
    assert!(f.check().await.is_err());
    assert!(log.push(&f.pool()).await.is_err());
    assert_eq!(
        access_store::connect::backoff(Duration::ZERO),
        access_store::connect::BACKOFF_MIN
    );
    assert_eq!(
        access_store::connect::backoff(Duration::from_secs(4)),
        access_store::connect::BACKOFF_MAX
    );
    sh(&["promote", "sb_a"]).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let moved = loop {
        if let Ok(Some(host)) = f.check().await {
            break host;
        }
        assert!(
            Instant::now() < deadline,
            "the pool did not follow the promote"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(moved, hosts[1]);
    assert_eq!(f.host(), hosts[1]);
    let promoted = attach_at(&url("sb_a"), &db.name).await.unwrap();
    log.lease = next_leader(&promoted, &log.id, "w7").await;
    log.pos = read_head(&promoted.sequencer, &log.id).await.unwrap().pos;
    let (pos, _) = log.push(&f.pool()).await.unwrap();
    assert_eq!(
        read_head(&promoted.sequencer, &log.id).await.unwrap().pos,
        pos
    );
    sh(&["down"]).await;
}

/// Whether `pool` reaches a standby.
async fn standby(pool: &sqlx::PgPool) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT pg_is_in_recovery()")
        .fetch_one(pool)
        .await
        .unwrap()
}

// OPI-2, OP-27, OP-54-RL2, §17.4.6, Ek B 5997, 6094
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the replicated cell of scripts/pg-ha.sh (OP-158 m.3 (n))"]
async fn pg_ha_opi_2_the_replica_serves_listings_only_while_it_keeps_up() {
    let db = cell().await;
    let replica = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db, "sb_b", "access_test_app", &[]))
        .await
        .unwrap();
    let reads = ReplicaReads::new(db.app.clone(), replica, Duration::from_millis(500));
    assert!(!standby(reads.listing()).await, "out of use until probed");
    assert!(reads.probe().await);
    assert!(standby(reads.listing()).await);
    let mut log = Log::create(&db, 0x43).await;
    log.push(&db.sequencer).await.unwrap();
    let written = current_lsn(&db.app).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !standby(reads.own_profile(Some(written)).await).await {
        assert!(
            Instant::now() < deadline,
            "the replica never replayed the write"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let ahead = access_store::replica_reads::Lsn(written.0 + (1 << 40));
    assert!(!standby(reads.own_profile(Some(ahead)).await).await);
    sh(&["stop", "sb_b"]).await;
    for _ in 0..3 {
        log.push(&db.sequencer).await.unwrap();
    }
    assert!(!reads.probe().await);
    assert!(!standby(reads.listing()).await);
    assert!(!standby(reads.own_profile(None).await).await);
    sh(&["cont", "sb_b"]).await;
    sh(&["down"]).await;
}

// SA-47, SA-T16, TI-2, FA-13, OP-25, Ek B 5994, 6092
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the replicated cell of scripts/pg-ha.sh (OP-158 m.3 (n))"]
async fn pg_ha_sa_47_a_partitioned_old_primary_acknowledges_nothing_after_the_promote() {
    let db = cell().await;
    let mut log = Log::create(&db, 0x44).await;
    for _ in 0..3 {
        log.push(&db.sequencer).await.unwrap();
    }
    let before = log.pos;
    sh(&["stop", "primary"]).await;
    sh(&["promote", "sb_a"]).await;
    sh(&["cont", "primary"]).await;
    let old = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(role_options(
            &db,
            "primary",
            "access_test_sequencer",
            &[("synchronous_commit", "on")],
        ))
        .await
        .unwrap();
    let stale = tokio::time::timeout(Duration::from_secs(3), log.push(&old)).await;
    assert!(
        !matches!(stale, Ok(Ok(_))),
        "the partitioned primary acknowledged a commit: {stale:?}"
    );
    let promoted = attach_at(&url("sb_a"), &db.name).await.unwrap();
    assert_eq!(
        read_head(&promoted.sequencer, &log.id).await.unwrap().pos,
        before
    );
    let lease = next_leader(&promoted, &log.id, "w7-new").await;
    assert!(lease.epoch > log.lease.epoch);
    let mut next = Log {
        id: log.id,
        lease,
        pos: before,
        leaf: log.leaf,
        frontier: log.frontier.clone(),
    };
    next.push(&promoted.sequencer).await.unwrap();
    // TI-2
    log.pos = before + 1;
    assert!(matches!(
        log.push(&promoted.sequencer).await,
        Err(StoreError::HeadMoved)
    ));
    sh(&["kill", "primary"]).await;
    sh(&["down"]).await;
}
