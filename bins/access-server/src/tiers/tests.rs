#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use access_store::audit::open_month;
use access_store::audit_tier::moves;
use access_store::ephemeral::{open_days, partitions};
use access_store::testing::fresh;

use super::*;

fn now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn cold_dir() -> std::path::PathBuf {
    let n = access_crypto::random::bytes::<8>().unwrap();
    let name = format!("{:016x}", u64::from_be_bytes(n));
    std::env::temp_dir().join(format!("access-server-cold-{name}"))
}

// OP-73 m.7, OP-158 m.3 (w), OP-129 m.2
#[tokio::test]
async fn the_daily_job_closes_expired_ephemeral_days_once() {
    let db = fresh().await.unwrap();
    for o in open_days(&db.archive, 0, 0).await {
        o.result.unwrap();
    }
    let a = tick(&db.app, &db.archive, "node-a", (now(), None))
        .await
        .unwrap();
    assert_eq!(a.completed, 1);
    assert!(a.closed.contains(&String::from("dpop_replay_d0")));
    let b = tick(&db.app, &db.archive, "node-b", (now(), None))
        .await
        .unwrap();
    assert_eq!(b, Tick::default());
    assert!(
        !partitions(&db.owner, "auth_flows")
            .await
            .unwrap()
            .contains(&String::from("auth_flows_d0"))
    );
}

// OP-73 m.4, OP-40, OP-158 m.3 (w)
#[tokio::test]
async fn the_daily_job_moves_due_audit_partitions_only_with_a_cold_tier() {
    let db = fresh().await.unwrap();
    open_month(&db.archive, 2025, 4).await.unwrap();
    let hot = tick(&db.app, &db.archive, "node-a", (now(), None))
        .await
        .unwrap();
    assert_eq!(hot.moved, Vec::<String>::new());
    assert_eq!(moves(&db.archive).await.unwrap(), vec![]);
    let dir = cold_dir();
    let later = now() + DAY_MS;
    let t = tick(&db.app, &db.archive, "node-a", (later, Some(dir.as_path())))
        .await
        .unwrap();
    assert_eq!(t.moved, vec![String::from("identity_audit_202504_default")]);
    assert_eq!(t.completed, 2);
    let moved = moves(&db.archive).await.unwrap();
    assert_eq!(moved.len(), 1);
    assert!(dir.join(&moved[0].object_key).exists());
}
