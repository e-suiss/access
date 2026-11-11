//! The streamed Record Export on the real router, sequencer, store and signer (OP-158 m.3 (g),
//! m.5, OP-153 m.3 (gg)): a package of a range larger than a chunk comes whole in one stream
//! and verifies with the open Kernel alone, a digest package withholds the bodies and keeps
//! the leaves, the export is a recorded Exercise audited before it leaves, and no rate class
//! closes it.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_authority_core::domain::export::{Coverage, read_stream};
use access_http::adp::adapters::{Discovery, router as adp_router};
use access_http::adp::app::Service;
use access_http::{Limits, harden};
use access_kernel::combinator::Mode;
use access_kernel::intent::ParamValue;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::scope::DomainId;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};

use super::super::authzen::{PEP, Pdp, pdp};
use super::replica::{as_pep, call, checkpoint, commit_export, domain_path};

/// The ADP and export routes reading a package `chunk` records at a time.
pub(super) fn routes(p: &Pdp, chunk: u64) -> axum::Router {
    let limits = Limits::default();
    let routes = adp_router(
        Service::new(p.w.domains.clone(), limits.max_body_bytes),
        Discovery {
            issuer: String::from("https://access.test"),
        },
    )
    .merge(access_http::mirror::router_with_chunk(
        p.w.domains.clone(),
        limits.max_body_bytes,
        chunk,
    ));
    as_pep(harden(routes, limits), PEP)
}

pub(super) async fn start(
    p: &Pdp,
    router: &axum::Router,
    body: &serde_json::Value,
) -> (StatusCode, Vec<u8>, Option<String>) {
    let r = tower::ServiceExt::oneshot(
        router.clone(),
        Request::post(format!(
            "/access/v1/domains/{}/exports",
            domain_path(&p.domain)
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap(),
    )
    .await
    .unwrap();
    let status = r.status();
    let location = r
        .headers()
        .get(header::CONTENT_LOCATION)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 26)
        .await
        .unwrap()
        .to_vec();
    (status, bytes, location)
}

// AP-14, INV-27, PI-6, TN-79, B3, G28, SI-15, OP-158 m.3 (g)
#[tokio::test(flavor = "multi_thread")]
async fn a_full_export_streams_whole_in_chunks_is_a_recorded_exercise_and_no_rate_class_closes_it()
{
    let label = "w3-export";
    let p = pdp(label).await;
    let router = routes(&p, 3);
    for _ in 0..4 {
        let a = p
            .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
            .await;
        assert_eq!(a.status, StatusCode::OK);
    }
    let size = checkpoint(&p, label).await;
    let body = commit_export(
        &p,
        &router,
        &[("disclosure", ParamValue::Enum(String::from("full")))],
    )
    .await;
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    let (status, package, location) = start(&p, &router, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&package)
    );
    let read = read_stream(&package).unwrap();
    assert_eq!(read.range, (0, head));
    assert_eq!(read.coverage, Coverage::Full);
    assert_eq!(read.records.len() as u64, head + 1);
    assert!(head + 1 > 3 * 3, "more records than three chunks: {head}");
    let cp =
        access_store::authority_checkpoint::latest(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
            .await
            .unwrap()
            .unwrap();
    assert!(read.checkpoints.iter().any(|n| n == &cp.note));
    if read.size == size {
        assert_eq!(read.root, cp.root);
    }
    // G28, SI-15
    let nonce = b64url_decode(body["context"]["nonce"].as_str().unwrap()).unwrap();
    let row =
        access_store::authority::find_nonce(&p.w.db.app, &DomainId::from_bytes(p.domain.0), &nonce)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.outcome, "allow");
    assert_eq!(
        read.export_exercise,
        access_kernel::meta::exercise_id(&p.domain, &nonce).unwrap()
    );
    // B18, OP-35
    let location = location.unwrap();
    for _ in 0..=access_authority_core::rate::EXPLAIN.0 {
        let (s, again) = call(
            &router,
            Request::get(format!("{location}?from=4"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let r = read_stream(&again).unwrap();
        assert_eq!((r.range, r.size, r.root), ((4, head), read.size, read.root));
    }
    // TN-79
    let elsewhere = as_pep(
        harden(
            access_http::mirror::router(p.w.domains.clone(), 1 << 16),
            Limits::default(),
        ),
        "another-pep",
    );
    let (s, _) = call(
        &elsewhere,
        Request::get(location.clone()).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // N-11, §7.9.12.5
    let redacted = commit_export(&p, &router, &[]).await;
    let (status, digest, _) = start(&p, &router, &redacted).await;
    assert_eq!(status, StatusCode::OK);
    let d = read_stream(&digest).unwrap();
    assert_eq!(d.coverage, Coverage::Digest);
    assert!(
        d.records
            .iter()
            .skip(1)
            .all(|r| r.opened.keys().all(|k| k == "versions"))
    );
    let now = p.w.domains.head(p.domain).await.unwrap().0;
    assert_eq!(d.range, (0, now));
    assert!(d.records.len() > read.records.len());
    // PI-4
    let mut forged = redacted.clone();
    forged["context"]["nonce"] = serde_json::Value::from(b64url_encode(
        &access_crypto::random::bytes::<16>().unwrap(),
    ));
    let (status, _, _) = start(&p, &router, &forged).await;
    assert!(status.is_client_error(), "{status}");
    p.w.domains.release().await;
}
