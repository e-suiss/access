//! The realm surface over HTTP: routes, the `Host`-selected realm, its stored issuer and its
//! JWKS headers.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    reason = "test code with fakes of async ports; the request-path lints (OP-3) do not apply"
)]

use access_http::realm::router;
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry, Unavailable};
use access_store::identity::RealmId;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

struct Rows;

fn entry(n: u8, slug: &str, issuer: &str) -> RealmEntry {
    RealmEntry {
        realm: RealmId::from_bytes([n; 16]),
        slug: slug.to_owned(),
        issuer: Issuer::parse(issuer).unwrap(),
    }
}

impl Directory for Rows {
    async fn by_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok((host == "acme.id.test").then(|| entry(1, "acme", "https://acme.id.test")))
    }

    async fn by_slug(&self, slug: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok((slug == "beta").then(|| entry(2, "beta", "https://id.test/realms/beta")))
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        Ok(Vec::new())
    }
}

struct KeySet;

impl Keys for KeySet {
    async fn ping(&self) -> Result<(), Unavailable> {
        Ok(())
    }

    async fn jwks(&self, realm: RealmId) -> Result<String, Unavailable> {
        if realm.as_bytes()[0] == 2 {
            return Err(Unavailable);
        }
        Ok(String::from(r#"{"keys":[{"kid":"k1"}]}"#))
    }
}

fn app() -> Router {
    router(Discovery::new(Rows, KeySet))
}

async fn get(path: &str, host: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app()
        .oneshot(
            Request::get(path)
                .header(header::HOST, host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

// TN-10, §17.9.6, §10.4.6: both discovery documents and the PRM of a subdomain realm name its
// stored issuer byte for byte
#[tokio::test]
async fn a_subdomain_realm_serves_its_documents() {
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (status, headers, body) = get(path, "acme.id.test").await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert!(
            body.contains(r#""issuer":"https://acme.id.test""#),
            "{body}"
        );
    }
    let (status, _, body) = get("/.well-known/oauth-protected-resource", "acme.id.test").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#""authorization_servers":["https://acme.id.test"]"#),
        "{body}"
    );
}

// CR-25, CMP-15.1: the JWKS carries its media type and cache policy
#[tokio::test]
async fn the_jwks_has_its_media_type_and_cache_policy() {
    let (status, headers, body) = get("/jwks.json", "acme.id.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/jwk-set+json");
    assert_eq!(
        headers[header::CACHE_CONTROL],
        "max-age=300, stale-while-revalidate=600, stale-if-error=86400"
    );
    assert_eq!(body, r#"{"keys":[{"kid":"k1"}]}"#);
}

// TN-10, §11.4.5: a path realm answers at every well-known variant; its signer outage is 503
#[tokio::test]
async fn a_path_realm_answers_at_every_variant() {
    for path in [
        "/.well-known/openid-configuration/realms/beta",
        "/realms/beta/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server/realms/beta",
        "/.well-known/oauth-protected-resource/realms/beta",
    ] {
        let (status, _, body) = get(path, "id.test").await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.contains("https://id.test/realms/beta"), "{body}");
    }
    let (status, headers, _) = get("/realms/beta/jwks.json", "id.test").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
}

// §17.9.6: an unknown host gets the router's 404, which names no realm
#[tokio::test]
async fn an_unknown_host_gets_a_plain_404() {
    for (path, host) in [
        ("/.well-known/openid-configuration", "evil.test"),
        ("/jwks.json", "evil.test"),
        ("/jwks.json", "acme.id.test:8443"),
        ("/realms/beta/jwks.json", "acme.id.test"),
        ("/.well-known/openid-configuration/realms/acme", "id.test"),
    ] {
        let (status, headers, body) = get(path, host).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} {host}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
        assert!(!body.contains("acme") && !body.contains("beta"), "{body}");
        assert_eq!(
            body,
            r#"{"type":"about:blank","title":"Not Found","status":404,"code":"not_found"}"#
        );
    }
}
