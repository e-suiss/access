//! Identity signer unreachable: token issuance stops with 503 (§16.7.1).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};

use super::super::management::send;
use super::identity;

fn userinfo() -> Request<Body> {
    Request::get("/realms/acme/userinfo")
        .header(header::HOST, "access.test")
        .header(
            header::AUTHORIZATION,
            "Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.e30.c2ln",
        )
        .body(Body::empty())
        .unwrap()
}

// FO-22, CMP-22b, G50, MD-8, §16.7.1, OP-158 m.3 (t), Ek B 6002, 6003
#[tokio::test(flavor = "multi_thread")]
async fn fo_22_without_the_identity_signer_nothing_is_signed_and_the_answer_is_503() {
    let (w, oauth) = identity("fo-22-identity-signer").await;
    let (r, _) = send(&oauth, userinfo()).await;
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "a token it cannot read is refused"
    );
    std::fs::remove_file(&w.identity_signer).unwrap();
    let (r, body) = send(&oauth, userinfo()).await;
    assert_eq!(
        r.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(r.headers().get("retry-after").is_some());
}
