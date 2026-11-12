#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

//! Hybrid receipts on the real server path (CR-42 m.4, L0-SIG-75a, OP-159 m.15 (b)): ML-DSA
//! admitted through the algorithm route behind its CT3 time-lock, an ALLOW committed through the
//! real decision point and signer, and the receipt checked by the real `access-verify` binary
//! and the SDK verifier, which accept it only with both components.

use std::process::Command;

use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Mode;
use access_kernel::json::b64url_decode;
use access_kernel::receipt::{Expected, Receipt};
use access_kernel::verify::hybrid::HybridError;
use access_kernel::verify::key_scope::{DomainMetadata, Hybrid};
use access_verifier::artefact::{self, SentError};
use axum::body::Body;
use axum::http::{Request, StatusCode};

use super::super::authzen::{PEP, pdp_timed};
use super::export::routes;
use super::replica::{bin, call, signer_socket};

fn wall() -> u64 {
    access_authority_signer::adapters::now_ms()
}

fn after_lock() -> u64 {
    wall() + crate::algorithms::LOCK_MS + 1_000
}

struct NoDecision;

impl access_http::adp::ports::Pdp for NoDecision {
    fn evaluate(
        &self,
        _: access_authority_core::app::Incoming,
    ) -> impl std::future::Future<
        Output = Result<access_authority_core::app::Response, access_authority_core::CoreError>,
    > + Send {
        std::future::ready(Err(access_authority_core::CoreError::Protocol(
            "not-reached",
        )))
    }
}

async fn post(router: axum::Router, uri: &str, body: &str) -> (u16, serde_json::Value) {
    use tower::ServiceExt as _;
    let mut req = Request::post(uri)
        .body(Body::from(body.to_owned()))
        .unwrap();
    req.extensions_mut()
        .insert(access_http::adp::adapters::Pep("pep-j2c".into()));
    let r = router.oneshot(req).await.unwrap();
    let status = r.status().as_u16();
    let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or_default())
}

fn verify(args: &[&str]) -> (bool, String) {
    let out = Command::new(bin("esuiss-access-verify", "access-verify"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut h, x| {
        let _ = std::fmt::Write::write_fmt(&mut h, format_args!("{x:02x}"));
        h
    })
}

// CR-42 m.4, L0-SIG-75a, L2-RCP-2, L2-RCP-3, SAI-44, OP-159 m.3 (e), m.9 (h), m.15 (b), m.16 (a)
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines, reason = "one walkthrough of a hybrid receipt")]
async fn a_hybrid_receipt_from_the_real_server_verifies_only_with_both_components() {
    use suiss_crypto::cose::Algorithm;
    let label = "j2c-hybrid";
    let p = pdp_timed(label, Some(0)).await;
    let d = p.domain;
    let socket = signer_socket(label);
    let algorithms = |now: fn() -> u64| {
        access_http::algorithms::router(
            crate::algorithms::PgAlgorithms {
                socket: socket.clone(),
                app: p.w.db.app.clone(),
                sequencer: p.w.db.sequencer.clone(),
                targets: Vec::new(),
                notify: None,
            },
            NoDecision,
            now,
        )
    };
    let origin = access_authority_sequencer::checkpoint::origin(&d);
    let admit = format!("/access/v1/domains/{origin}/algorithms");

    // OP-159 m.16 (a)
    let (s, b) = post(algorithms(wall), &admit, r#"{"alg":-49}"#).await;
    assert_eq!((s, b["status"].as_str()), (202, Some("time-lock")), "{b}");
    let (s, b) = post(algorithms(after_lock), &admit, r#"{"alg":-49}"#).await;
    assert_eq!((s, b["status"].as_str()), (200, Some("admitted")), "{b}");
    let signed = p.w.domains.metadata(d).await.unwrap();
    let payload = suiss_crypto::cose::parse_sign1(&signed)
        .unwrap()
        .payload
        .unwrap();
    let metadata = DomainMetadata::from_bytes(&payload).unwrap();
    assert!(metadata.algorithms.contains(&Algorithm::MlDsa65));
    assert_eq!(metadata.hybrid, Some(Hybrid::Both));

    // L2-RCP-2, OP-159 m.15 (b)
    let router = routes(&p, 512);
    let (s, body) = call(
        &router,
        Request::post("/access/v1/evaluation")
            .header("content-type", "application/json")
            .body(Body::from(p.allowed(Mode::Commit).await.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let member = |k: &str| {
        b64url_decode(answer["context"]["receipt"][k].as_str().unwrap_or_default()).unwrap()
    };
    let (carrier, excerpt, pq_excerpt) = (member("sign1"), member("excerpt"), member("pq_excerpt"));
    let (classic, pq) = access_kernel::verify::hybrid::decode_carrier(&carrier).unwrap();
    let claimed = Receipt::from_bytes(
        &suiss_crypto::cose::parse_sign1(&classic)
            .unwrap()
            .payload
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claimed.audience, PEP);

    // L0-SIG-75a, SAI-44
    let root = std::env::temp_dir().join(format!("j2c-hybrid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let file = |name: &str, bytes: &[u8]| {
        let path = root.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let (m_file, c_file, x_file, px_file, classic_file, pq_file) = (
        file("metadata.cbor", &payload),
        file("carrier.cbor", &carrier),
        file("excerpt.cose", &excerpt),
        file("pq-excerpt.cose", &pq_excerpt),
        file("classic.cose", &classic),
        file("pq.cose", &pq),
    );
    let (d_hex, i_hex, now) = (
        hex(&d.0),
        hex(&claimed.intent.0),
        (claimed.iat + 1).to_string(),
    );
    let run = |receipt: &str, pq_excerpt: Option<&str>| {
        let mut a = vec![
            "receipt",
            "--metadata",
            m_file.as_str(),
            "--receipt",
            receipt,
            "--excerpt",
            x_file.as_str(),
            "--domain",
            d_hex.as_str(),
            "--audience",
            PEP,
            "--intent",
            i_hex.as_str(),
            "--now",
            now.as_str(),
        ];
        if let Some(px) = pq_excerpt {
            a.extend(["--pq-excerpt", px]);
        }
        verify(&a)
    };
    let (ok, text) = run(&c_file, Some(&px_file));
    assert!(
        ok && text.contains(&hex(&claimed.to_bytes().unwrap())),
        "{text}"
    );
    let (ok, text) = run(&c_file, None);
    assert!(!ok && text.contains("reject: hybrid-missing"), "{text}");
    let (ok, text) = run(&classic_file, None);
    assert!(!ok && text.contains("reject: hybrid-missing"), "{text}");
    let (ok, text) = run(&pq_file, Some(&px_file));
    assert!(!ok && text.contains("reject: hybrid-missing"), "{text}");

    // OP-159 m.15 (b)
    let expected = Expected {
        domain: &d,
        audience: PEP,
        intent: &claimed.intent,
        now: claimed.iat + 1,
    };
    let sdk = |sign1: &[u8], pq: Option<&[u8]>| {
        artefact::receipt(
            &suiss_crypto::aws::AwsLcBackend,
            &metadata,
            (sign1, &excerpt, pq),
            &expected,
            None,
        )
    };
    assert_eq!(sdk(&carrier, Some(&pq_excerpt)), Ok(claimed.clone()));
    assert_eq!(
        sdk(&classic, None),
        Err(SentError::Hybrid(HybridError::Missing))
    );
    assert_eq!(
        sdk(&carrier, None),
        Err(SentError::Hybrid(HybridError::Missing))
    );
    let pep = access_sdk::authorize::Pep {
        audience: String::from(PEP),
        domain: d,
        metadata: metadata.clone(),
    };
    let ours = |sign1: &[u8], pq: Option<&[u8]>| {
        pep.receipt(
            &suiss_crypto::aws::AwsLcBackend,
            (sign1, &excerpt, pq),
            &claimed.intent,
            claimed.iat + 1,
            None,
        )
    };
    assert_eq!(ours(&carrier, Some(&pq_excerpt)), Ok(claimed.clone()));
    assert_eq!(
        ours(&classic, None),
        Err(access_sdk::authorize::Denied::Hybrid(HybridError::Missing))
    );

    // OP-149 m.9
    let exercise = access_kernel::json::b64url_encode(&claimed.exercise.0);
    let kept =
        p.w.domains
            .exercise_record(d, claimed.exercise)
            .await
            .unwrap();
    let (sign1, slot) = kept.unwrap().signed_receipt.unwrap();
    assert_eq!(sign1, carrier, "{exercise}");
    assert_eq!(
        access_authority_core::app::hybrid::split(&slot),
        (excerpt.clone(), Some(pq_excerpt.clone()))
    );
    let _ = std::fs::remove_dir_all(&root);
}
