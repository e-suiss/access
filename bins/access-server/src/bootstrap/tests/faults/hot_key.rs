//! Hot domain or hot key: bounded retries, then "Busy — retry" (§16.7, TI-9).

use access_kernel::combinator::Mode;
use axum::http::StatusCode;

use super::super::authzen::{PEP, pdp};

// FO-10, TI-9, MD-8, §16.7, §17.7.1, OP-158 m.3 (t), (v)
#[tokio::test(flavor = "multi_thread")]
async fn fo_10_a_held_domain_answers_busy_and_never_allows() {
    let p = pdp("fo-10-hot").await;
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    let lock = access_store::testing::hold_head(&p.w.db, p.domain.0)
        .await
        .unwrap();
    let first = p.allowed(Mode::Commit).await;
    let adp = p.adp.clone();
    let blocked = tokio::spawn(async move {
        let mut req = axum::http::Request::post("/access/v1/evaluation")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(first.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(access_http::adp::adapters::Pep(String::from(PEP)));
        tower::ServiceExt::oneshot(adp, req).await.unwrap().status()
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["reason"], "busy", "{v}");
    assert_eq!(a.headers["retry-after"], "1");
    assert!(v.get("decision").is_none(), "{v}");
    assert_eq!(p.w.domains.head(p.domain).await.unwrap().0, head);
    drop(lock);
    assert_eq!(blocked.await.unwrap(), StatusCode::OK);
    p.w.domains.release().await;
}
