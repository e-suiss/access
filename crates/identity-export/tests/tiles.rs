//! OP-37, OP-158 m.3 (w): the identity audit tree as C2SP tiles on a real PostgreSQL, and the
//! yearly shard frozen as static tiles in the cold tier.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Mutex;

use access_identity_audit::AuditError;
use access_identity_audit::adapters::PgAudit;
use access_identity_audit::app::identity_step;
use access_identity_audit::app::tiles::{extend, freeze, freeze_due};
use access_identity_audit::domain::tiles::{log_dir, path, tile_root};
use access_identity_audit::ports::{ColdStore as _, NoteSigner, TileStore as _};
use access_identity_export::adapters::cold_file::FileCold;
use access_identity_signer::adapters::SealedFactory;
use access_identity_signer::cell::CellKey;
use access_store::audit::{CheckpointRow, last_checkpoint};
use access_store::audit_tiles::shards;
use access_store::testing::{TestDb, age_audit_checkpoints, bulk_audit_rows, fresh};
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
        CellKey::generate("cell-t", &mut factory).unwrap(),
    ))
}

fn cold_dir() -> FileCold {
    let n = access_crypto::random::bytes::<8>().unwrap();
    FileCold {
        root: std::env::temp_dir().join(format!("access-tiles-{:016x}", u64::from_be_bytes(n))),
    }
}

const NOW: u64 = 1_793_000_000_000;

async fn integrated(db: &TestDb, signer: &Cell, rows: u64) -> CheckpointRow {
    let log = PgAudit(db.checkpointer.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        identity_step(&log, signer, NOW).await.unwrap();
        if let Some(c) = last_checkpoint(&db.checkpointer).await.unwrap()
            && c.size >= rows
        {
            return c;
        }
        assert!(std::time::Instant::now() < deadline, "rows not integrated");
        tokio::task::yield_now().await;
    }
}

async fn tile(cold: &FileCold, dir: &str, level: u8, n: u64, w: Option<u64>) -> Vec<[u8; 32]> {
    let b = cold
        .get(&format!("{dir}/{}", path(level, n, w)))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("tile {level}/{n} {w:?}"));
    b.as_chunks::<32>().0.to_vec()
}

// OP-37, OP-158 m.3 (w)
#[tokio::test(flavor = "multi_thread")]
async fn a_frozen_year_is_static_tiles_that_give_its_checkpoint() {
    let db = fresh().await.unwrap();
    let signer = cell();
    bulk_audit_rows(&db, [0x61; 16], 70_000).await.unwrap();
    let cp = integrated(&db, &signer, 70_000).await;
    let log = PgAudit(db.checkpointer.clone());
    assert_eq!(extend(&log, &cp).await.unwrap(), 273 + 1);
    assert_eq!(extend(&log, &cp).await.unwrap(), 0);

    let cold = cold_dir();
    let mut wrong = cp.clone();
    wrong.root = [0; 32];
    assert!(matches!(
        freeze((&log, &cold), 2025, Some(&wrong)).await,
        Err(AuditError::Proof)
    ));
    assert_eq!(shards(&db.checkpointer).await.unwrap(), vec![]);

    let shard = freeze((&log, &cold), 2025, Some(&cp)).await.unwrap();
    assert_eq!(
        (shard.size, shard.root, shard.tiles),
        (70_000, cp.root, 273 + 1 + 1 + 1 + 1)
    );
    let origin = cp.note.as_deref().unwrap().lines().next().unwrap();
    let dir = log_dir(origin);
    let mut leaves = Vec::new();
    for n in 0..273 {
        leaves.extend(tile(&cold, &dir, 0, n, None).await);
    }
    leaves.extend(tile(&cold, &dir, 0, 273, Some(112)).await);
    assert_eq!(
        tile_root(&leaves).unwrap(),
        cp.root,
        "the static tiles alone give the checkpoint"
    );
    assert_eq!(tile(&cold, &dir, 1, 1, Some(17)).await.len(), 17);
    assert_eq!(tile(&cold, &dir, 2, 0, Some(1)).await.len(), 1);
    let note = cold
        .get(&format!("{dir}/shards/2025/checkpoint"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(note, cp.note.clone().unwrap().into_bytes());
    assert!(
        freeze((&log, &cold), 2025, Some(&cp)).await.is_err(),
        "a year freezes once"
    );
}

// OP-37, OP-158 m.3 (w)
#[tokio::test(flavor = "multi_thread")]
async fn every_ended_year_is_frozen_once() {
    let db = fresh().await.unwrap();
    let signer = cell();
    bulk_audit_rows(&db, [0x62; 16], 300).await.unwrap();
    integrated(&db, &signer, 300).await;
    let log = PgAudit(db.checkpointer.clone());
    let cold = cold_dir();
    assert_eq!(freeze_due(&log, &cold).await.unwrap(), vec![]);
    age_audit_checkpoints(&db, 2).await.unwrap();
    let frozen = freeze_due(&log, &cold).await.unwrap();
    let (_, now) = log.years().await.unwrap();
    assert_eq!(
        frozen.iter().map(|s| s.year).collect::<Vec<_>>(),
        vec![now - 2, now - 1]
    );
    assert_eq!(frozen[0].size, 300);
    assert_eq!(frozen[1].size, 300, "a quiet year freezes at the same tree");
    assert_eq!(freeze_due(&log, &cold).await.unwrap(), vec![]);
}
