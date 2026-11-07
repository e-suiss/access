//! E10, X21: published Schema Publication Packages against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::publications::{Kept, PublicationRow, keep, of_namespace};
use access_store::testing::fresh;

fn row(fingerprint: u8, version: u64) -> PublicationRow {
    PublicationRow {
        fingerprint: [fingerprint; 32],
        publisher: [7; 16],
        namespace: "commerce".to_owned(),
        catalog_version: version,
        package: vec![fingerprint],
        published_ms: 1_000,
    }
}

// E10: a published version is immutable; the same package is kept once, another under the
// same version is refused
#[tokio::test]
async fn a_published_version_is_kept_once_and_never_replaced() {
    let db = fresh().await.unwrap();
    assert_eq!(keep(&db.app, &row(1, 2)).await.unwrap(), Kept::New);
    assert_eq!(keep(&db.app, &row(1, 2)).await.unwrap(), Kept::Same);
    assert_eq!(keep(&db.app, &row(2, 2)).await.unwrap(), Kept::VersionTaken);
    assert_eq!(keep(&db.app, &row(3, 3)).await.unwrap(), Kept::New);
    let listed = of_namespace(&db.app, "commerce").await.unwrap();
    assert_eq!(
        listed.iter().map(|r| r.catalog_version).collect::<Vec<_>>(),
        [3, 2]
    );
    assert_eq!(listed[1].package, vec![1]);
    assert_eq!(of_namespace(&db.app, "other").await.unwrap(), []);
}

// OP-73, E10: neither the app role nor anyone else changes or removes a published row
#[tokio::test]
async fn a_published_row_is_never_updated_or_deleted() {
    let db = fresh().await.unwrap();
    keep(&db.app, &row(1, 1)).await.unwrap();
    for pool in [&db.app, &db.owner] {
        for sql in [
            "UPDATE access.schema_publication SET package = '\\x00'",
            "DELETE FROM access.schema_publication",
        ] {
            let changed = sqlx::query(sql)
                .execute(pool)
                .await
                .map_or(0, |r| r.rows_affected());
            assert_eq!(changed, 0, "{sql}");
        }
    }
    let listed = of_namespace(&db.app, "commerce").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].package, vec![1]);
}
