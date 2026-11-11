//! OP-73 m.7, OP-146 m.5 (f), OP-158 m.3 (w): the archive job closes ephemeral protocol day
//! partitions past their TTL and nothing else, against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::audit::open_month;
use access_store::ephemeral::{close_days, open_days, partitions};
use access_store::testing::fresh;

fn today() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    i32::try_from(secs / 86_400).unwrap()
}

// OP-73 m.7, OP-158 m.3 (w)
#[tokio::test]
async fn only_ephemeral_days_past_their_ttl_are_closed() {
    let db = fresh().await.unwrap();
    let now = today();
    for o in open_days(&db.archive, 0, 0).await {
        o.result.unwrap();
    }
    for o in open_days(&db.archive, now - 10, 10).await {
        o.result.unwrap();
    }
    open_month(&db.archive, 1970, 1).await.unwrap();
    let mut closed = close_days(&db.archive).await.unwrap();
    closed.sort();
    let old = format!("dpop_replay_d{}", now - 10);
    assert!(closed.contains(&String::from("auth_flows_d0")));
    assert!(closed.contains(&String::from("oauth_codes_d0")));
    assert!(closed.contains(&String::from("claim_ingest_d0")));
    assert!(closed.contains(&String::from("login_throttle_19700101")));
    assert!(closed.contains(&old), "{closed:?}");
    let throttle = partitions(&db.owner, "login_throttle").await.unwrap();
    assert_eq!(throttle.len(), 12, "{throttle:?}");
    let replay = partitions(&db.owner, "dpop_replay").await.unwrap();
    for keep in [now - 2, now - 1, now] {
        assert!(
            replay.contains(&format!("dpop_replay_d{keep}")),
            "{replay:?}"
        );
    }
    assert!(!replay.contains(&format!("dpop_replay_d{}", now - 3)));
    let audit = partitions(&db.owner, "identity_audit").await.unwrap();
    assert!(audit.contains(&String::from("identity_audit_197001")));
    assert_eq!(close_days(&db.archive).await.unwrap(), Vec::<String>::new());
}

// OP-73 m.7
#[tokio::test]
async fn only_the_archive_role_closes_days() {
    let db = fresh().await.unwrap();
    assert!(close_days(&db.app).await.is_err());
    assert!(close_days(&db.checkpointer).await.is_err());
}
