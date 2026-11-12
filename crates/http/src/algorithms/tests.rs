#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_authority_core::CoreError;
use access_authority_core::app::Response as Decided;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use super::*;

struct Fake;

impl Algorithms for Fake {
    fn admit(
        &self,
        _: Digest,
        alg: Algorithm,
        now: u64,
    ) -> impl Future<Output = Result<Admission, AlgorithmError>> + Send {
        std::future::ready(match alg {
            Algorithm::MlDsa65 => Ok(Admission::Locked(now + 1)),
            Algorithm::MlDsa87 => Ok(Admission::Admitted),
            _ => Err(AlgorithmError::Conflict),
        })
    }

    fn reanchor(
        &self,
        _: Digest,
        _: bool,
        _: u64,
    ) -> impl Future<Output = Result<Reanchored, AlgorithmError>> + Send {
        std::future::ready(Err(AlgorithmError::NoPqWitness))
    }

    fn retirable(
        &self,
        _: Digest,
        _: Algorithm,
        _: u64,
    ) -> impl Future<Output = Result<u64, AlgorithmError>> + Send {
        std::future::ready(Err(AlgorithmError::ReanchorRequired))
    }

    fn retire(
        &self,
        _: Digest,
        _: (Algorithm, Digest, u64),
        _: u64,
    ) -> impl Future<Output = Result<(), AlgorithmError>> + Send {
        std::future::ready(Ok(()))
    }
}

struct NoPdp;

impl Pdp for NoPdp {
    fn evaluate(&self, _: Incoming) -> impl Future<Output = Result<Decided, CoreError>> + Send {
        std::future::ready(Err(CoreError::Protocol("never")))
    }
}

fn now() -> u64 {
    7
}

fn domain() -> String {
    format!(
        "sha-256:{}",
        access_kernel::json::b64url_encode(&[0x11; 32])
    )
}

async fn post_to(path: &str, body: &str, pep: bool) -> (StatusCode, serde_json::Value) {
    let mut req = Request::post(path.replace("{domain}", &domain()))
        .body(Body::from(body.to_owned()))
        .unwrap();
    if pep {
        req.extensions_mut().insert(Pep(String::from("pep")));
    }
    let res = router(Fake, NoPdp, now).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

// OP-159 m.3 (e), m.9 (h)
#[tokio::test]
async fn an_admission_waits_out_the_time_lock_and_names_its_refusals() {
    let (s, b) = post_to(ADMIT_PATH, r#"{"alg":-49}"#, true).await;
    assert_eq!(
        (s, b["status"].as_str(), b["wait_until"].as_u64()),
        (StatusCode::ACCEPTED, Some("time-lock"), Some(8))
    );
    let (s, b) = post_to(ADMIT_PATH, r#"{"alg":-50}"#, true).await;
    assert_eq!(
        (s, b["status"].as_str()),
        (StatusCode::OK, Some("admitted"))
    );
    let (s, b) = post_to(ADMIT_PATH, r#"{"alg":-19}"#, true).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("algorithm-profile-conflict"))
    );
    let (s, _) = post_to(ADMIT_PATH, r#"{"alg":-1}"#, true).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = post_to(ADMIT_PATH, r#"{"alg":-49}"#, false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

// CR-45 RA-6, RB-0, OP-159 m.3 (f), (g)
#[tokio::test]
async fn a_re_anchor_without_a_pq_witness_and_a_retirement_without_a_body_are_refused() {
    let (s, b) = post_to(REANCHOR_PATH, "", true).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("reanchor-no-pq-witness"))
    );
    let (s, _) = post_to(REANCHOR_PATH, "", false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = post_to(RETIRE_PATH, "{}", true).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = post_to(RETIRE_PATH, "{}", false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
