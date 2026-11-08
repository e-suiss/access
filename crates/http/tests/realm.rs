//! The realm surface over HTTP: routes, the `Host`-selected realm, its stored issuer and its
//! JWKS headers.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    reason = "test code with fakes of async ports; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use access_http::realm::router;
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::domain::suiss::Settings;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry, Unavailable};
use access_store::identity::{RealmId, TenantId};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

struct Rows;

fn entry(n: u8, slug: &str, issuer: &str) -> RealmEntry {
    RealmEntry {
        tenant: TenantId::from_bytes([n; 16]),
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

fn settings() -> Settings {
    Settings {
        region: "eu-central".to_owned(),
        relay: "https://relay.test".to_owned(),
        management_api: "https://api.test".to_owned(),
        api_base: "https://access.test".to_owned(),
        products: BTreeMap::from([("work".to_owned(), "https://work.test".to_owned())]),
    }
}

fn app() -> Router {
    router(Discovery::new(Rows, KeySet).with_suiss(settings()))
}

// OP-149 m.3
#[tokio::test]
async fn a_realm_serves_its_suiss_configuration() {
    let (status, headers, body) = get("/.well-known/suiss-configuration", "acme.id.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(headers[header::CACHE_CONTROL], "max-age=300");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["suiss_configuration_version"], 1);
    assert_eq!(doc["issuer"], "https://acme.id.test");
    assert_eq!(doc["suiss_region"], "eu-central");
    assert_eq!(doc["suiss_relay"], "https://relay.test");
    assert_eq!(doc["suiss_management_api"], "https://api.test");
    assert_eq!(doc["suiss_products"]["work"], "https://work.test");
    assert_eq!(
        doc["endpoints"]["key_lookup"],
        "https://access.test/access/v1/keys/{kid}"
    );
    assert_eq!(
        doc["endpoints"]["adp"],
        "https://access.test/.well-known/authzen-configuration"
    );
    // OP-149 m.6, m.8
    assert_eq!(
        doc["endpoints"]["auth_context"],
        "https://acme.id.test/v1/me/auth-context"
    );
    assert_eq!(
        doc["endpoints"]["instances"],
        "https://acme.id.test/v1/me/instances"
    );
    // OP-149 m.7, m.17a
    assert_eq!(
        doc["suiss_event_subscriptions"]["ssf_configuration"],
        "https://acme.id.test/.well-known/ssf-configuration"
    );
    assert_eq!(
        doc["suiss_event_subscriptions"]["webhooks"],
        "urn:suiss:access:delivery:webhook"
    );
    for path in [
        "/.well-known/suiss-configuration/realms/beta",
        "/realms/beta/.well-known/suiss-configuration",
    ] {
        let (status, _, body) = get(path, "id.test").await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.contains(r#""issuer":"https://id.test/realms/beta""#));
        assert!(body.contains(
            r#""ssf_configuration":"https://id.test/.well-known/ssf-configuration/realms/beta""#
        ));
    }
    let (status, _, _) = get("/.well-known/suiss-configuration", "evil.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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

// TN-10, §17.9.6, §10.4.6
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

// CR-25, CMP-15.1
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

// TN-10, §11.4.5
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

// §17.9.6
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
            r#"{"type":"about:blank","title":"Not Found","status":404,"code":"not-found"}"#
        );
    }
}
