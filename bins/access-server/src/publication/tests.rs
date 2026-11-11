#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::print_stderr,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use access_identity_audit::adapters::SignerNotes;
use access_identity_audit::domain::verify;
use access_identity_audit::ports::ColdStore as _;
use access_identity_export::adapters::publish::note_key;
use access_identity_signer::protocol::{Request, Response};
use access_store::audit::{AuditEvent, CheckpointRow};
use access_store::audit_publication::published_through;
use access_store::identity::{Cursor, RealmId, TenantId, TenantTx};
use access_store::testing::{TestDb, fresh, server_version};
use suiss_crypto::envelope::SoftKek;

use super::*;
use crate::checkpoints::{AUDIT_INTERVAL, audit_tick};

const T: TenantId = TenantId::from_bytes([0x41; 16]);
const R: RealmId = RealmId::from_bytes([0x42; 16]);

fn random_name() -> String {
    format!(
        "{:016x}",
        u64::from_be_bytes(access_crypto::random::bytes::<8>().unwrap())
    )
}

/// A real identity signer with its cell key open, on a socket of its own.
fn identity_signer() -> PathBuf {
    use access_identity_signer::adapters::{DirVault, SealedFactory, now_ms, serve};
    let dir = std::env::temp_dir().join(format!("acpub-{}", random_name()));
    std::fs::create_dir_all(&dir).unwrap();
    let kek = access_crypto::random::bytes::<32>().unwrap();
    let mut service = access_identity_signer::service::Service::start(
        SealedFactory::new(SoftKek::new("identity-kek", kek)),
        DirVault::new(&dir),
        suiss_crypto::rotation::Policy::REALM,
    )
    .unwrap();
    service.open_cell("cell-p1").unwrap();
    let path = dir.join("s.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        listener,
        Arc::new(Mutex::new(service)),
        vec![uid],
        now_ms,
    ));
    path
}

fn targets(dir: &std::path::Path) -> Targets {
    Targets {
        store: Some(StoreNotes {
            store: FileCold {
                root: dir.to_path_buf(),
            },
        }),
        hooks: Vec::new(),
    }
}

async fn write_row(db: &TestDb, n: u32) {
    let target = format!("usr_{n}");
    let correlation = format!("req_{n}");
    let mut t = TenantTx::begin(&db.app, T, R).await.unwrap();
    t.audit(&AuditEvent {
        event_type: "session.revoked",
        actor: "adm_1",
        target: &target,
        correlation: &correlation,
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
}

fn wall() -> u64 {
    use access_identity_account::ports::Clock as _;
    access_identity_account::adapters::system::SystemClock.now_ms()
}

/// The checkpointer's loop as `Checkpointers::start` runs it: integrate and sign, then publish.
fn spawn_loop(db: &TestDb, socket: PathBuf, publication: Targets) -> tokio::task::JoinHandle<()> {
    let checkpointer = db.checkpointer.clone();
    tokio::spawn(async move {
        let signer = SignerNotes(socket);
        let mut every = tokio::time::interval(AUDIT_INTERVAL);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            audit_tick(&checkpointer, "a", &signer, wall()).await;
            tick(&checkpointer, &publication).await;
        }
    })
}

// U52, OP-37, OP-38, OP-150 m.3 (h)
#[tokio::test(flavor = "multi_thread")]
async fn an_identity_audit_row_is_in_a_signed_checkpoint_at_its_publication_target() {
    let db = fresh().await.unwrap();
    let socket = identity_signer();
    let dir = std::env::temp_dir().join(format!("acpub-cold-{}", random_name()));
    let running = spawn_loop(&db, socket.clone(), targets(&dir));
    write_row(&db, 1).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    while published_through(&db.checkpointer, "object-store")
        .await
        .unwrap()
        < 1
    {
        assert!(Instant::now() < deadline, "no publication after 30 s");
        tokio::task::yield_now().await;
    }
    running.abort();
    let Ok(Response::CellKey { origin, vkey }) =
        access_identity_signer::adapters::call(&socket, &Request::CellKey).await
    else {
        panic!("cell key");
    };
    let store = FileCold { root: dir };
    let note = String::from_utf8(store.get(&note_key(&origin, 1)).await.unwrap().unwrap()).unwrap();
    let row = access_store::audit::pending(&db.checkpointer, Cursor::default(), 1)
        .await
        .unwrap();
    let leaf = access_identity_audit::domain::leaf(&row[0]).unwrap();
    let published = CheckpointRow {
        size: 1,
        root: leaf,
        frontier: vec![leaf],
        cursor: access_identity_audit::domain::Leaf::cursor(&row[0]),
        note: Some(note),
    };
    verify(&access_crypto::AwsLcBackend, &published, &origin, &vkey).unwrap();
    assert_eq!(tick(&db.checkpointer, &targets(&store.root)).await, 0);
}

// U52, OP-38
#[tokio::test(flavor = "multi_thread")]
async fn identity_audit_rows_reach_publication_within_the_declared_interval() {
    const ROWS: u32 = 40;
    let db = fresh().await.unwrap();
    let socket = identity_signer();
    let dir = std::env::temp_dir().join(format!("acpub-mmd-{}", random_name()));
    let running = spawn_loop(&db, socket, targets(&dir));
    let mut latencies = Vec::new();
    let mut pace = tokio::time::interval(Duration::from_millis(73));
    for n in 1..=ROWS {
        pace.tick().await;
        write_row(&db, n).await;
        let committed = Instant::now();
        let deadline = committed + Duration::from_secs(30);
        while published_through(&db.checkpointer, "object-store")
            .await
            .unwrap()
            < u64::from(n)
        {
            assert!(
                Instant::now() < deadline,
                "row {n} not published after 30 s"
            );
            tokio::task::yield_now().await;
        }
        latencies.push(committed.elapsed());
    }
    running.abort();
    latencies.sort();
    let at = |q: f64| latencies[((latencies.len() - 1) as f64 * q).round() as usize];
    eprintln!(
        "U52 identity MMD: rows={ROWS} interval_ms={} p50_ms={} p99_ms={} max_ms={} cores={} pg={} os={} arch={}",
        AUDIT_INTERVAL.as_millis(),
        at(0.5).as_millis(),
        at(0.99).as_millis(),
        latencies.last().unwrap().as_millis(),
        std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        server_version(&db).await.unwrap(),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    assert_eq!(latencies.len(), ROWS as usize);
}
