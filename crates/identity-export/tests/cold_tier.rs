//! OP-40, OP-73 m.4, OP-138, OP-158 m.3 (w): the identity audit cold tier on a real PostgreSQL:
//! a partition moves only when its hot window is over and every row is checkpointed, its copy is
//! checked against the partition root before it is detached, and nothing is deleted.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Mutex;

use access_identity_audit::AuditError;
use access_identity_audit::adapters::{PgAudit, PgTiers};
use access_identity_audit::app::identity_step;
use access_identity_audit::app::tier::{move_due, read_moved};
use access_identity_audit::ports::{ColdCodec as _, ColdStore as _, NoteSigner, Tiers as _};
use access_identity_export::adapters::cold_file::FileCold;
use access_identity_export::domain::cold::ColdParquet;
use access_identity_signer::adapters::SealedFactory;
use access_identity_signer::cell::CellKey;
use access_store::audit::{last_checkpoint, open_month};
use access_store::audit_tier::moves;
use access_store::ephemeral::partitions;
use access_store::tenancy::create_tenant;
use access_store::testing::{
    TestDb, app_reads_cold_audit, cold_audit_rows, fresh, hot_audit_rows, past_audit_row,
    rewrite_cold_audit, set_audit_hot_days,
};
use suiss_crypto::envelope::SoftKek;

struct Cell(Mutex<CellKey>);

impl NoteSigner for Cell {
    fn key(&self) -> impl Future<Output = Result<(String, String), AuditError>> + Send {
        let key = self.0.lock().unwrap();
        std::future::ready(Ok((key.origin().to_owned(), key.vkey())))
    }

    fn sign(&self, body: String) -> impl Future<Output = Result<String, AuditError>> + Send {
        let key = self.0.lock().unwrap();
        std::future::ready(
            key.sign(&body)
                .map_err(|e| AuditError::Unsigned(e.code().to_owned())),
        )
    }
}

fn cell() -> Cell {
    let kek = access_crypto::random::bytes::<32>().unwrap();
    let mut factory = SealedFactory::new(SoftKek::new("identity-kek", kek));
    Cell(Mutex::new(
        CellKey::generate("cell-a", &mut factory).unwrap(),
    ))
}

fn cold_dir() -> FileCold {
    let n = access_crypto::random::bytes::<8>().unwrap();
    let name = format!("{:016x}", u64::from_be_bytes(n));
    FileCold {
        root: std::env::temp_dir().join(format!("access-cold-tier-{name}")),
    }
}

const NOW: u64 = 1_793_000_000_000;

/// Steps the checkpointer until its checkpoint holds `rows` rows: a row is integrated only
/// once every older transaction of the cluster has ended.
async fn checkpoint_all(db: &TestDb, signer: &Cell, rows: u64) {
    let log = PgAudit(db.checkpointer.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        identity_step(&log, signer, NOW).await.unwrap();
        let size = last_checkpoint(&db.checkpointer)
            .await
            .unwrap()
            .map_or(0, |c| c.size);
        if size >= rows {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "rows not integrated");
        tokio::task::yield_now().await;
    }
}

fn hex(b: [u8; 16]) -> String {
    format!("{:032x}", u128::from_be_bytes(b))
}

// OP-73 m.4, OP-158 m.3 (w), OP-40
#[tokio::test(flavor = "multi_thread")]
async fn a_due_partition_moves_to_the_cold_tier_verified_and_detached() {
    let db = fresh().await.unwrap();
    let signer = cell();
    let own = *create_tenant(&db.app, "pool-default")
        .await
        .unwrap()
        .as_bytes();
    open_month(&db.archive, 2025, 1).await.unwrap();
    for n in 0..3 {
        past_audit_row(&db, own, "2025-01-10T00:00:00Z", n)
            .await
            .unwrap();
    }
    past_audit_row(&db, [0x5a; 16], "2025-01-11T00:00:00Z", 9)
        .await
        .unwrap();
    let tiers = PgTiers(db.archive.clone());
    assert_eq!(
        tiers.due().await.unwrap(),
        vec![],
        "nothing is due before its checkpoint"
    );
    checkpoint_all(&db, &signer, 4).await;
    let due = tiers.due().await.unwrap();
    let names: Vec<&str> = due.iter().map(|d| d.partition.as_str()).collect();
    let own_name = format!("identity_audit_202501_t{}", hex(own));
    assert_eq!(
        names,
        vec!["identity_audit_202501_default", own_name.as_str()]
    );
    assert_eq!(due[1].tenant, Some(own));
    assert_eq!((due[0].rows, due[1].rows), (1, 3));

    let cold = cold_dir();
    let run = move_due(&tiers, &cold, &ColdParquet).await.unwrap();
    assert!(run.failed.is_empty(), "{:?}", run.failed);
    assert_eq!(run.moved.len(), 2);
    assert_eq!(hot_audit_rows(&db, "2025-01").await.unwrap(), 0);
    assert_eq!(cold_audit_rows(&db, &own_name).await.unwrap(), 3);
    assert_eq!(
        cold_audit_rows(&db, "identity_audit_202501_default")
            .await
            .unwrap(),
        1
    );
    let left = partitions(&db.owner, "identity_audit_202501")
        .await
        .unwrap();
    assert_eq!(left, Vec::<String>::new());
    let recorded = moves(&db.archive).await.unwrap();
    assert_eq!(recorded, run.moved);
    let back = read_moved((&cold, &ColdParquet), &recorded[1])
        .await
        .unwrap();
    assert_eq!(back.len(), 3);
    assert!(back.iter().all(|r| r.tenant == own));
    assert!(
        rewrite_cold_audit(&db, &own_name).await.is_err(),
        "a cold partition stays append-only"
    );
    assert!(
        app_reads_cold_audit(&db, &own_name).await.is_err(),
        "the application role cannot reach the cold schema"
    );
    let again = move_due(&tiers, &cold, &ColdParquet).await.unwrap();
    assert!(again.moved.is_empty() && again.failed.is_empty());
}

// OP-73 m.4
#[tokio::test(flavor = "multi_thread")]
async fn a_partition_whose_copy_does_not_match_stays_hot() {
    let db = fresh().await.unwrap();
    let signer = cell();
    let own = *create_tenant(&db.app, "pool-default")
        .await
        .unwrap()
        .as_bytes();
    open_month(&db.archive, 2025, 2).await.unwrap();
    past_audit_row(&db, own, "2025-02-03T00:00:00Z", 1)
        .await
        .unwrap();
    checkpoint_all(&db, &signer, 1).await;
    let tiers = PgTiers(db.archive.clone());
    let due = tiers.due().await.unwrap();
    let own_due = due.iter().find(|d| d.tenant.is_some()).unwrap();
    let cold = cold_dir();
    let key = access_identity_audit::domain::tier::object_key(&own_due.partition, own_due.month);
    cold.put(&key, &ColdParquet.encode(&[]).unwrap())
        .await
        .unwrap();
    let run = move_due(&tiers, &cold, &ColdParquet).await.unwrap();
    assert_eq!(run.failed.len(), 1);
    assert_eq!(run.failed[0].0, own_due.partition);
    assert!(run.moved.iter().all(|m| m.partition != own_due.partition));
    assert_eq!(hot_audit_rows(&db, "2025-02").await.unwrap(), 1);
    let recorded = moves(&db.archive).await.unwrap();
    assert!(recorded.iter().all(|m| m.partition != own_due.partition));
}

// OP-158 m.3 (w)
#[tokio::test(flavor = "multi_thread")]
async fn a_partition_inside_its_hot_window_is_not_due() {
    let db = fresh().await.unwrap();
    let signer = cell();
    let own = *create_tenant(&db.app, "pool-default")
        .await
        .unwrap()
        .as_bytes();
    set_audit_hot_days(&db, own, 3000).await.unwrap();
    open_month(&db.archive, 2025, 3).await.unwrap();
    past_audit_row(&db, own, "2025-03-03T00:00:00Z", 1)
        .await
        .unwrap();
    checkpoint_all(&db, &signer, 1).await;
    let due = PgTiers(db.archive.clone()).due().await.unwrap();
    assert!(
        due.iter().all(|d| !d.partition.contains(&hex(own))),
        "{due:?}"
    );
    assert!(
        set_audit_hot_days(&db, own, 29).await.is_err(),
        "a hot window under 30 days is refused"
    );
}
