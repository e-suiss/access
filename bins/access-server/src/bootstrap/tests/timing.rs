//! Response times an MCP client waits for (§11.4.5 #25, §11.5.6 #25, OP-153 m.3 (gg)): the
//! realm's discovery documents and its token endpoint answer within 10 s through the real
//! routers on the real sequencer and `SoftHSM`; the MCP server's protected resource metadata
//! within 5 s. Every answer is a whole body, and a stream tells a buffering reverse proxy not to
//! hold it.

use std::time::{Duration, Instant};

use access_identity_oauth::adapters::PgDirectory;
use access_identity_oauth::app::Discovery as RealmDiscovery;
use access_sdk::mcp::server::Stream;
use axum::body::{Body, HttpBody as _, to_bytes};
use axum::http::{Request as HttpRequest, StatusCode, header};
use tower::ServiceExt as _;

use super::exchange::{ACCESS_TOKEN_TYPE, ISSUER, Realm, UPSTREAM};
use super::mcp::metadata_answer;
use super::*;

const TOKEN_AND_DISCOVERY: Duration = Duration::from_secs(10);
const RESOURCE_METADATA: Duration = Duration::from_secs(5);

/// A `GET` of `path` on the realm's discovery routes: status, whether the body is whole (its
/// size known before it is sent, no chunked stream for a proxy to hold), and the time taken.
async fn discover(router: &axum::Router, path: &str) -> (StatusCode, bool, Duration) {
    let started = Instant::now();
    let r = router
        .clone()
        .oneshot(
            HttpRequest::get(path)
                .header(header::HOST, "access.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let whole = r.body().size_hint().exact().is_some()
        && !r.headers().contains_key(header::TRANSFER_ENCODING);
    let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
    let took = started.elapsed();
    assert!(!body.is_empty());
    (status, whole, took)
}

// §11.4.5 #25, AG-17, OP-154 m.3 (gg), Ek B 4579
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_and_the_token_endpoint_answer_within_ten_seconds() {
    let r = Realm::open("l10-timing").await;
    let discovery = access_http::realm::router(RealmDiscovery::new(
        PgDirectory::new(r.w.db.router.clone()),
        access_identity_oauth::adapters::SignerKeys::new(r.w.identity_signer.clone()),
    ));
    for path in [
        "/realms/acme/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server/realms/acme",
        "/realms/acme/jwks.json",
    ] {
        let (status, whole, took) = discover(&discovery, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(whole, "{path}");
        assert!(took < TOKEN_AND_DISCOVERY, "{path} took {took:?}");
    }

    let subject = r.subject_token(ISSUER).await;
    let started = Instant::now();
    let (status, body) = r
        .exchange(
            &r.a2,
            (&subject, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[],
        )
        .await;
    let took = started.elapsed();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["access_token"].is_string(), "{body}");
    assert!(
        took < TOKEN_AND_DISCOVERY,
        "the token endpoint took {took:?}"
    );
    r.w.domains.release().await;
}

// §11.5.6 #25, RS-M1, OP-154 m.3 (gg), Ek B 4579
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_metadata_answers_within_five_seconds_and_a_stream_is_never_held() {
    let (r, took) = metadata_answer("l10-timing-prm").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(took < RESOURCE_METADATA, "the metadata took {took:?}");
    let value = |name: &str| {
        r.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(value("content-type"), Some("application/json"));
    assert!(value("transfer-encoding").is_none());
    assert!(r.body.contains("\"authorization_servers\""), "{}", r.body);

    let stream = Stream::headers();
    let header = |name: &str| {
        stream
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(header("content-type"), Some("text/event-stream"));
    assert_eq!(header("x-accel-buffering"), Some("no"));
    assert_eq!(header("cache-control"), Some("no-store"));
}
