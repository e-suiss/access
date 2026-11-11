#![allow(clippy::unwrap_used, reason = "test code")]

use access_store::ephemeral::{open_days, partitions};
use access_store::testing::fresh;

use super::*;

// OP-73 m.7, OP-158 m.3 (w), OP-129 m.2
#[tokio::test]
async fn the_daily_job_closes_expired_ephemeral_days_once() {
    let db = fresh().await.unwrap();
    for o in open_days(&db.archive, 0, 0).await {
        o.result.unwrap();
    }
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let a = tick(&db.app, &db.archive, "node-a", now).await.unwrap();
    assert_eq!(a.completed, 1);
    assert!(a.closed.contains(&String::from("dpop_replay_d0")));
    let b = tick(&db.app, &db.archive, "node-b", now).await.unwrap();
    assert_eq!(b, Tick::default());
    assert!(
        !partitions(&db.owner, "auth_flows")
            .await
            .unwrap()
            .contains(&String::from("auth_flows_d0"))
    );
}
