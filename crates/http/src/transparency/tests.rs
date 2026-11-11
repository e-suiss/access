#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt as _;

use super::*;

struct One(Vec<Declared>);

impl Checkpoints for One {
    fn listing(
        &self,
        _: Digest,
    ) -> impl Future<Output = Result<Option<Listing>, InclusionError>> + Send {
        std::future::ready(Ok(Some(Listing {
            witnessed_through: 3,
            latest: Some(("note\n".into(), vec![1])),
            witnesses: self.0.clone(),
        })))
    }

    fn inclusion(
        &self,
        _: Digest,
        size: u64,
        _: u64,
    ) -> impl Future<Output = Result<Vec<u8>, InclusionError>> + Send {
        std::future::ready(if size == 9 {
            Err(InclusionError::NotWitnessed)
        } else {
            Ok(vec![0xa0])
        })
    }

    fn tile(
        &self,
        _: Digest,
        _: u32,
        index: u64,
        width: u64,
    ) -> impl Future<Output = Result<Vec<u8>, InclusionError>> + Send {
        std::future::ready(if index == 1_234_067 && width == 5 {
            Ok(vec![1; 160])
        } else {
            Err(InclusionError::Unknown)
        })
    }
}

fn w(independent: bool) -> Declared {
    Declared {
        vkey: "w+00000000+AA".into(),
        operator: "x".into(),
        independent,
    }
}

async fn get(router: Router, uri: &str, pep: bool) -> (StatusCode, String) {
    let mut req = Request::get(uri).body(Body::empty()).unwrap();
    if pep {
        req.extensions_mut().insert(Pep("pep".into()));
    }
    let r = router.oneshot(req).await.unwrap();
    let status = r.status();
    let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn d() -> String {
    format!("sha-256:{}", access_kernel::json::b64url_encode(&[7; 32]))
}

// U9, HL-7, P4
#[tokio::test]
async fn equivocation_is_claimed_detectable_only_with_compared_independent_witnesses() {
    for (ws, claim) in [
        (vec![w(true)], false),
        (vec![w(false), w(false)], false),
        (vec![w(true), w(false)], true),
    ] {
        let (s, body) = get(
            router(One(ws)),
            &format!("/access/v1/domains/{}/checkpoints", d()),
            false,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["claims"]["equivocation_detectable"], claim, "{body}");
        assert_eq!(v["witnessed_through"], 3);
    }
}

// T19, §17.6.1 rule 5, SEC23
#[tokio::test]
async fn an_inclusion_bundle_needs_a_pep_and_a_witnessed_checkpoint() {
    let uri = |size: u64, pos: u64| {
        format!(
            "/access/v1/domains/{}/checkpoints/{size}/inclusion/{pos}",
            d()
        )
    };
    let r = || router(One(vec![w(true)]));
    assert_eq!(
        get(r(), &uri(4, 1), false).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(get(r(), &uri(4, 1), true).await.0, StatusCode::OK);
    assert_eq!(get(r(), &uri(9, 1), true).await.0, StatusCode::CONFLICT);
    assert_eq!(get(r(), &uri(4, 4), true).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        get(
            r(),
            &format!("/access/v1/domains/{}/checkpoints/04/inclusion/1", d()),
            true
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

// K15
#[test]
fn tile_paths_are_canonical() {
    assert_eq!(tile_index("000"), Some((0, 256)));
    assert_eq!(tile_index("x001/x234/067"), Some((1_234_067, 256)));
    assert_eq!(tile_index("x001/x234/067.p/5"), Some((1_234_067, 5)));
    for bad in [
        "1",
        "x000/001",
        "x1/234",
        "001/002",
        "067.p/256",
        "067.p/0",
        "067.p/05",
    ] {
        assert_eq!(tile_index(bad), None, "{bad}");
    }
}

// K15
#[tokio::test]
async fn a_tile_is_served_as_concatenated_hashes() {
    let (s, body) = get(
        router(One(vec![])),
        &format!("/access/v1/domains/{}/tile/0/x001/x234/067.p/5", d()),
        false,
    )
    .await;
    assert_eq!((s, body.len()), (StatusCode::OK, 160));
}
