#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use axum::body::{Body, to_bytes};
use axum::http::Request;
use tower::ServiceExt as _;

use super::*;

struct One;

impl StatusLists for One {
    async fn latest(&self, domain: Digest, list_no: u64) -> Result<Option<Served>, Unavailable> {
        match (domain.0[0], list_no) {
            (1, 0) => Ok(Some(Served {
                token: vec![0xd2, 0x84],
                excerpt: Some(vec![1, 2, 3]),
                as_of: 42,
            })),
            (2, _) => Err(Unavailable),
            _ => Ok(None),
        }
    }
}

fn uri(seed: u8, list: &str) -> String {
    format!(
        "/access/v1/status-lists/{list}?domain=sha-256:{}",
        b64url_encode(&[seed; 32])
    )
}

async fn get(path: &str, if_none_match: Option<&str>) -> Response {
    let mut req = Request::get(path);
    if let Some(tag) = if_none_match {
        req = req.header("if-none-match", tag);
    }
    router(One)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

// OP-150 m.3 (a), (s), CR-58 m.1: the list is served as application/statuslist+cwt with its key
// excerpt, a short cache lifetime and the reflected position as its ETag
#[tokio::test]
async fn the_latest_list_is_served_with_its_excerpt() {
    let r = get(&uri(1, "0"), None).await;
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers();
    assert_eq!(h[header::CONTENT_TYPE], CWT_CONTENT_TYPE);
    assert_eq!(h[header::CACHE_CONTROL], CACHE);
    assert_eq!(h[header::ETAG], "\"42\"");
    assert_eq!(h[EXCERPT_HEADER], b64url_encode(&[1, 2, 3]));
    let body = to_bytes(r.into_body(), 1 << 16).await.unwrap();
    assert_eq!(body.as_ref(), [0xd2, 0x84]);
    let again = get(&uri(1, "0"), Some("\"42\"")).await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
}

// OP-150 m.3 (a), PI-9: an unknown list or domain is 404, a store outage 503 and never an
// empty list; a malformed domain is 400
#[tokio::test]
async fn no_list_is_never_an_empty_list() {
    assert_eq!(
        get(&uri(1, "1"), None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&uri(1, "00"), None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&uri(1, "x"), None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&uri(3, "0"), None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&uri(2, "0"), None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get("/access/v1/status-lists/0?domain=nope", None)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get("/access/v1/status-lists/0", None).await.status(),
        StatusCode::BAD_REQUEST
    );
}
