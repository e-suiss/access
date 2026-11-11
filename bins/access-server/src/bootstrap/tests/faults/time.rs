//! Time sources disagree: commit stops with "Unavailable — time check" (§16.7, TI-RT2).

use access_kernel::combinator::Mode;
use axum::http::StatusCode;

use super::super::authzen::pdp;

// FO-04, TI-RT2, K-2, TI-19, §16.7, §17.7.1, OP-158 m.3 (t)
#[tokio::test(flavor = "multi_thread")]
async fn fo_04_a_clock_ahead_of_its_witness_stops_every_commit_until_they_agree() {
    use access_authority_sequencer::witness::{cross_check, time_check};
    let p = pdp("fo-04-time").await;
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    let now = p.now().await;
    assert!(cross_check(now + 120_000, now / 1000).is_err());
    assert!(time_check().is_err());
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["code"], "unavailable", "{v}");
    assert_eq!(
        v["reason"], "time",
        "shown as \"Unavailable — time check\": {v}"
    );
    assert_eq!(
        p.w.domains.head(p.domain).await.unwrap().0,
        head,
        "nothing committed"
    );
    assert!(cross_check(now, now / 1000 + 1).is_ok());
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.json());
    p.w.domains.release().await;
}
