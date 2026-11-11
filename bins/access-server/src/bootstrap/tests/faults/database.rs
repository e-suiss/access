//! Authority database loss: commit stops and no ALLOW is answered (§16.7, §17.7.1).

use std::time::Duration;

use access_kernel::combinator::Mode;
use axum::http::StatusCode;

use super::super::authzen::pdp;

// FO-02, TI-2, TI-8, TI-9, MD-8, §16.7, §17.7.1, OP-158 m.3 (t)
#[tokio::test(flavor = "multi_thread")]
async fn fo_02_with_the_authority_database_gone_nothing_commits_and_nothing_is_allowed() {
    let p = pdp("fo-02-database").await;
    let body = p.allowed(Mode::Commit).await;
    access_store::testing::refuse_connections(&p.w.db, true)
        .await
        .unwrap();
    let a = tokio::time::timeout(
        Duration::from_secs(90),
        p.post("/access/v1/evaluation", &body),
    )
    .await
    .unwrap();
    let v = a.json();
    assert_eq!(a.status, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert!(
        v.get("decision").is_none(),
        "no decision without the log: {v}"
    );
    access_store::testing::refuse_connections(&p.w.db, false)
        .await
        .unwrap();
    // TI-8: the same nonce commits once the primary answers again
    let mut answered = None;
    for _ in 0..40 {
        let a = p.post("/access/v1/evaluation", &body).await;
        if a.status == StatusCode::OK {
            answered = Some(a.json());
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let v = answered.unwrap();
    assert_eq!(v["decision"], true, "{v}");
    p.w.domains.release().await;
}
