//! Access keeps no queue of pending changes (X5, C26, §8.17.9.5, OP-157 m.3 (u), Ek B 5558):
//! on a freshly migrated database no table holds one; governance quorums live in the coordinator.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::testing::fresh;

// X5, C26, §8.17.9.5, OP-157 m.3 (u), Ek B 5558
#[tokio::test]
async fn no_table_holds_a_pending_change() {
    let db = fresh().await.unwrap();
    let queues: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'access' \
         AND (table_name LIKE '%pending_change%' OR table_name LIKE '%approval_queue%' \
              OR table_name LIKE '%request_queue%' OR table_name LIKE '%change_queue%')",
    )
    .fetch_one(&db.owner)
    .await
    .unwrap();
    assert_eq!(queues, 0);
}
