//! Signer crash: no signature leaves and nothing unsigned stands in for one (§16.7, §17.7.1,
//! TI-12).

use access_kernel::combinator::Mode;
use axum::http::StatusCode;

use super::super::authzen::pdp;
use super::signer_socket;

// FO-09, FO-08, TI-12, §16.7, §17.7.1, §14.8, OP-158 m.3 (t)
#[tokio::test(flavor = "multi_thread")]
async fn fo_09_with_the_signer_gone_a_decision_carries_no_signed_artefact() {
    let label = "fo-09-signer";
    let p = pdp(label).await;
    let before = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(before.status, StatusCode::OK);
    assert!(
        before.json()["context"]["receipt"].is_object(),
        "{}",
        before.json()
    );
    std::fs::remove_file(signer_socket(label)).unwrap();
    let body = p.allowed(Mode::Commit).await;
    let a = p.post("/access/v1/evaluation", &body).await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    // TI-12: the outcome is recorded, the artefact waits; nothing unsigned is handed out
    assert!(v["context"].get("receipt").is_none(), "{v}");
    assert!(v["context"].get("pap").is_none(), "{v}");
    let row = p.recorded(&body).await;
    assert!(p.w.domains.head(p.domain).await.unwrap().0 >= row.decision_pos);
    p.w.domains.release().await;
}
