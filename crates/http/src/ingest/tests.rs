use std::sync::Mutex;

use access_internal_api::claims::Quarantine;
use access_internal_api::idp::Unavailable;
use access_kernel::model::Id;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt as _;

use super::*;

const PEP_THUMB: [u8; 32] = [9; 32];

#[derive(Default)]
struct Seen(Mutex<Vec<ClaimSubmission>>);

impl ClaimIngest for Seen {
    fn ingest(
        &self,
        submission: ClaimSubmission,
    ) -> impl std::future::Future<Output = Result<ClaimVerdict, Unavailable>> + Send {
        let verdict = match submission.claim.first() {
            Some(1) => Ok(ClaimVerdict::Admitted {
                claim: Id([1; 16]),
                position: 7,
                replayed: false,
            }),
            Some(2) => Ok(ClaimVerdict::Quarantined {
                claim: Id([2; 16]),
                position: 8,
                reason: Quarantine::Quota,
            }),
            Some(3) => Ok(ClaimVerdict::Rejected {
                code: "claim-signature".to_owned(),
            }),
            _ => Err(Unavailable("x".to_owned())),
        };
        if let Ok(mut s) = self.0.lock() {
            s.push(submission);
        }
        std::future::ready(verdict)
    }
}

fn body(carrier: &str, claim: u8) -> String {
    json!({
        "domain": format!("sha-256:{}", b64url_encode(&[1; 32])),
        "carrier": carrier,
        "claim": b64url_encode(&[claim]),
    })
    .to_string()
}

async fn post_as(
    app: Router,
    pep: Option<&str>,
    key: Option<&str>,
    json: String,
) -> (StatusCode, Value) {
    let mut req = Request::post(PATH).header("content-type", "application/json");
    if let Some(k) = key {
        req = req.header("idempotency-key", k);
    }
    let mut req = req.body(Body::from(json)).unwrap_or_default();
    if let Some(p) = pep {
        req.extensions_mut().insert(Pep(p.to_owned()));
    }
    let res = app.oneshot(req).await.unwrap_or_default();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), MAX_BODY)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// CMP-8, §9.13 rule 3, OP-65
#[tokio::test]
async fn the_endpoint_answers_the_disposition() {
    let app = || router(Seen::default());
    let pep = b64url_encode(&PEP_THUMB);
    let (s, v) = post_as(app(), Some(&pep), Some("k"), body("cose", 1)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["disposition"], "admit");
    assert_eq!(v["position"], "7");
    let (s, v) = post_as(app(), Some(&pep), Some("k"), body("cose", 2)).await;
    assert_eq!((s, v["reason"].as_str()), (StatusCode::OK, Some("quota")));
    let (s, v) = post_as(app(), Some(&pep), Some("k"), body("cose", 3)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["code"], "claim-signature");
    let (s, _) = post_as(app(), Some(&pep), Some("k"), body("cose", 4)).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

// L1-ADP-2, L2-CLM-5, OP-65
#[tokio::test]
async fn the_caller_and_channel_come_from_the_transport() {
    let pep = b64url_encode(&PEP_THUMB);
    let (s, _) = post_as(router(Seen::default()), None, Some("k"), body("cose", 1)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = post_as(router(Seen::default()), Some(&pep), None, body("cose", 1)).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("idempotency-key-required"))
    );
    let (s, v) = post_as(
        router(Seen::default()),
        Some(&pep),
        Some("k"),
        body("saml", 1),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("ingest-carrier"))
    );
    let sub = decode(body("unsigned", 1).as_bytes(), &pep);
    assert_eq!(
        sub.as_ref().map(|s| (s.carrier, s.domain)),
        Ok((Carrier::Unsigned(Channel::Pep(PEP_THUMB)), Digest([1; 32])))
    );
    assert_eq!(
        decode(body("unsigned", 1).as_bytes(), "not-a-thumbprint").err(),
        Some("pep-unauthenticated")
    );
    let extra = json!({ "domain": "x", "carrier": "cose", "claim": "AQ", "subject": "y" });
    assert!(decode(extra.to_string().as_bytes(), &pep).is_err());
}
