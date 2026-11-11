//! Witness outage: a revocation takes effect at once and its ack waits for a cosign (§16.7,
//! SEC23, CL-2).

use access_kernel::combinator::Mode;
use axum::http::StatusCode;

use super::super::authzen::{PEP, pdp};
use super::position;

// FO-06, SEC23, CL-2, TI-6, TI-13, §16.7, §17.7.1, OP-158 m.3 (t)
#[tokio::test(flavor = "multi_thread")]
async fn fo_06_without_a_witness_a_revocation_is_recorded_and_its_ack_waits() {
    let p = pdp("fo-06-witness").await;
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let intent = p
        .idp_intent(access_internal_api::idp::IdpAction::OrgInviteRevoke, "org")
        .await;
    let body = p
        .body(Mode::Commit, &nonce, &intent, p.idp_basis(), PEP)
        .await;
    let a = p.post("/access/v1/evaluation", &body).await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    assert_eq!(
        v["decision"], true,
        "the revocation took effect at commit: {v}"
    );
    assert_eq!(
        v["context"]["ack"], "pending",
        "never confirmed without a cosign (CL-2): {v}"
    );
    let row = p.recorded(&body).await;
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    assert!(head >= row.decision_pos, "the record is in the log");
    let through = position(&v["context"]["witnessed_through"]);
    assert!(through.is_none_or(|t| t < row.decision_pos), "{v}");
    // §17.7.1: the client asks again with the same nonce; the outcome stays, the ack still waits
    let again = p.post("/access/v1/evaluation", &body).await;
    let w = again.json();
    assert_eq!(again.status, StatusCode::OK, "{w}");
    assert_eq!(w["context"]["replayed"], true, "{w}");
    assert_eq!(w["context"]["ack"], "pending", "{w}");
    assert_eq!(p.recorded(&body).await.decision_pos, row.decision_pos);
    assert_eq!(p.w.domains.head(p.domain).await.unwrap().0, head);
    p.w.domains.release().await;
}
