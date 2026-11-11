//! Named fault-injection tests, one per failure-contract row (§16.7, §16.7.1, OP-158 m.3 (t)),
//! against the real router on real PostgreSQL, sequencer and `SoftHSM`. The rows, their owners
//! and the test that proves each are `conformance/catalog/failure-ownership.toml`.

use std::sync::Arc;
use std::time::Duration;

use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::oauth::PgOAuth;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::dpop::DpopProfile;
use serde_json::Value as Json;

use super::*;

mod database;
mod derived;
mod failover;
mod hot_key;
mod hsm;
mod identity_db;
mod identity_signer;
mod signer;
mod time;
mod witness;

/// A position the ADP answer names as a decimal string.
fn position(v: &Json) -> Option<u64> {
    v.as_str().and_then(|s| s.parse().ok())
}

/// The authority signer socket [`authority_signer`] serves for `label`.
fn signer_socket(label: &str) -> std::path::PathBuf {
    std::env::temp_dir()
        .join(format!("abs-auth-{label}-{}", std::process::id()))
        .join("a.sock")
}

/// The realm authorization server's routes of `w`, as the server builds them, with no SAML,
/// client certificates, bundles, hooks, claims or CIBA.
fn oauth_routes(w: &World) -> axum::Router {
    use access_identity_oauth::ports::oauth as po;
    use access_identity_oauth::ports::profile as pp;
    access_http::oauth::router(OAuth::new(crate::oauth::ServerEnv {
        saml: Arc::new(pp::NoSamlAssertions),
        client_certificates: Arc::new(pp::NoClientCertificates),
        db: PgOAuth::with_reader(w.db.app.clone(), w.db.reader.clone()),
        signer: SignerKeys::new(w.identity_signer.clone()),
        client_keys: HttpClientKeys::new(
            Outbound::disabled(Duration::from_secs(5)),
            CachePolicy::default(),
        ),
        documents: access_identity_oauth::adapters::cimd::HttpClientDocuments::new(
            Outbound::disabled(Duration::from_secs(5)),
        ),
        bundles: Arc::new(access_identity_attest::ports::NoBundles),
        workload_trust: Arc::new(po::NoWorkloadTrust),
        standing: Arc::new(w.plane.clone()),
        directory: PgDirectory::new(w.db.router.clone()),
        app: w.db.app.clone(),
        nonces: crate::oauth::HsmNonces::new(w.keys.clone()),
        dpop: DpopProfile::default(),
        projections: w.plane.clone(),
        tenant_ids: Arc::new(crate::ids::CellIds::new(w.keys.clone())),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        management: Arc::new(crate::admin::tokens::PlaneHolders(w.plane.clone(), None)),
        claims: Arc::new(po::NoClaims),
        issuers: Arc::new(w.plane.clone()),
        ciba: Arc::new(po::NoCiba),
        geo: Arc::new(po::NoGeo),
    }))
}

/// `w` bootstrapped from the local plan, its authorization server's routes.
async fn identity(label: &str) -> (World, axum::Router) {
    let w = World::new(label).await;
    w.run(&plan()).await;
    w.domains.release().await;
    let routes = oauth_routes(&w);
    (w, routes)
}

/// A form POST to the realm `acme` at `path`.
fn form(
    path: &str,
    body: &str,
    authorization: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    let mut b = axum::http::Request::post(format!("/realms/acme{path}"))
        .header(axum::http::header::HOST, "access.test")
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        );
    if let Some(a) = authorization {
        b = b.header(axum::http::header::AUTHORIZATION, a);
    }
    b.body(axum::body::Body::from(body.to_owned())).unwrap()
}

#[derive(serde::Deserialize)]
struct Ownership {
    failure: Vec<Row>,
}

#[derive(serde::Deserialize)]
struct Row {
    id: String,
    owner: String,
    unknown: String,
    missing: String,
    safe_default: String,
    text: String,
    tests: Vec<String>,
    pending: Option<String>,
}

// XI-20, §7.9.14, §16.7, §16.7.1, OP-158 m.3 (t), Ek B 5894, 6001, 6002
#[test]
fn every_failure_row_names_its_owner_its_unknown_its_safe_default_and_a_test_that_exists() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let table: Ownership = toml::from_str(
        &std::fs::read_to_string(root.join("conformance/catalog/failure-ownership.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(table.failure.len(), 22);
    let owners = [
        "access", "provider", "relay", "executor", "domain", "idp", "verifier", "operator",
    ];
    for r in &table.failure {
        assert!(owners.contains(&r.owner.as_str()), "{}: {}", r.id, r.owner);
        for (name, v) in [
            ("unknown", &r.unknown),
            ("missing", &r.missing),
            ("safe_default", &r.safe_default),
        ] {
            assert!(!v.trim().is_empty(), "{}: {name}", r.id);
        }
        let key = format!("{} =", r.text);
        assert!(
            ["hub", "account", "login"].iter().any(|f| {
                std::fs::read_to_string(root.join(format!("locales/en/{f}.ftl")))
                    .unwrap()
                    .lines()
                    .any(|l| l.starts_with(&key))
            }),
            "{}: {} is no message",
            r.id,
            r.text
        );
        assert!(
            !r.tests.is_empty() || r.pending.as_deref().is_some_and(|p| !p.is_empty()),
            "{} has no test and does not say what it waits for",
            r.id
        );
        for t in &r.tests {
            let (file, name) = t.split_once("::").unwrap();
            let src = std::fs::read_to_string(root.join(file)).unwrap();
            assert!(src.contains(&format!("fn {name}(")), "{}: {t}", r.id);
            assert!(
                src.contains(&r.id) || !file.contains("/faults/"),
                "{}: {file} cites it",
                r.id
            );
        }
    }
}
