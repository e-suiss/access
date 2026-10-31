//! OP-141 m.22 (g), (k), INV-33: the derived index against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::StoreError;
use access_store::authority::{LogRecord, create_domain};
use access_store::derived::{GrantRow, advance, cursor, grants_for, grants_in};
use access_store::scope::DomainId;
use access_store::testing::fresh;

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];

fn row(grant: u8, kind: &'static str, holder: Option<u8>, ended: bool) -> GrantRow {
    GrantRow {
        grant: [grant; 16],
        holder_kind: kind,
        holder: holder.map(|h| [h; 16]),
        namespace: "shop".to_owned(),
        ended,
        pos: 1,
    }
}

// OP-141 m.22 (g): the cursor moves only from where it is; candidates come by namespace or
// holder, live ones only
#[tokio::test]
async fn the_index_follows_its_cursor() {
    let db = fresh().await.unwrap();
    let d = DomainId::from_bytes([3; 32]);
    let genesis = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1_000,
        leaf_hash: [2; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, TENANT, &genesis, &[])
        .await
        .unwrap();
    assert_eq!(cursor(&db.app, &d).await.unwrap(), 0);
    let rows = [
        row(1, "party", Some(9), false),
        row(2, "public", None, false),
        row(3, "party", Some(8), false),
        row(4, "party", Some(9), true),
    ];
    advance(&db.deriver, &d, 0, 5, &rows).await.unwrap();
    assert_eq!(cursor(&db.app, &d).await.unwrap(), 5);
    assert!(matches!(
        advance(&db.deriver, &d, 0, 6, &[]).await,
        Err(StoreError::Stale)
    ));
    assert!(matches!(
        advance(&db.deriver, &d, 4, 6, &[]).await,
        Err(StoreError::Stale)
    ));
    assert_eq!(
        grants_in(&db.app, &d, "shop", None, 10).await.unwrap(),
        [[1; 16], [2; 16], [3; 16]]
    );
    assert_eq!(
        grants_in(&db.app, &d, "shop", Some([1; 16]), 1)
            .await
            .unwrap(),
        [[2; 16]]
    );
    assert_eq!(
        grants_for(&db.app, &d, &[9; 16], None, 10).await.unwrap(),
        [[1; 16], [2; 16]]
    );
    // a change of the same Grant replaces its row
    advance(&db.deriver, &d, 5, 7, &[row(1, "party", Some(9), true)])
        .await
        .unwrap();
    assert_eq!(
        grants_for(&db.app, &d, &[9; 16], None, 10).await.unwrap(),
        [[2; 16]]
    );
}
