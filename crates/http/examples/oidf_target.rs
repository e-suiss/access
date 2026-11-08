//! The OpenID Foundation conformance target (OP-146 I11, §14.8 SA-T2, B9): one realm `acme`
//! seeded on the PostgreSQL at `DATABASE_URL` with the clients of
//! `conformance/oidf/access-oidcc.json` and `access-fapi2.json`, served over TLS 1.3 at `https://acme.id.test:9443`
//! with the realm, authorization server routes and a fixture sign-in page that starts a
//! session for the realm's one user. The nightly workflow points the conformance suite at it.
//! It is a test fixture: the sign-in page signs in without a credential.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixture; the request-path lints (OP-3) do not apply"
)]

#[path = "../../identity-oauth/tests/support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::sync::Arc;

use access_http::oauth::{SESSION_COOKIE, router as oauth_router};
use access_http::realm::router as realm_router;
use access_http::{Limits, harden};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::login::return_to_ok;
use access_identity_oauth::domain::request::Params;
use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rcgen::{CertificateParams, KeyPair};
use serde_json::Value;
use support::{Cluster, Extra, now};

/// The realm base of the target; the realm `acme` is `https://acme.id.test:9443`.
const BASE: &str = "https://id.test:9443";

fn conformance_dir() -> PathBuf {
    std::env::var_os("OIDF_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/oidf"),
        PathBuf::from,
    )
}

fn read(name: &str) -> Value {
    let path = conformance_dir().join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// The suite's clients: `client_secret_basic` for the OIDC Core plans and `private_key_jwt`
/// with the suite's public keys for the FAPI 2.0 plan (OP-152 m.5 (j)), each redirecting to
/// its plan's callback.
fn clients() -> Vec<Extra> {
    let plans = read("plans.json");
    let redirect = plans["redirect_uri"].as_str().unwrap().to_owned();
    let config = read("access-oidcc.json");
    let mut out: Vec<Extra> = ["client", "client2"]
        .iter()
        .map(|k| {
            (
                config[k]["client_id"].as_str().unwrap().to_owned(),
                String::from("client_secret_basic"),
                config[k]["client_secret"].as_str().unwrap().to_owned(),
                vec![redirect.clone()],
            )
        })
        .collect();
    let fapi = plans["plans"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["config"] == "access-fapi2.json")
        .unwrap();
    let fapi_redirect = fapi["redirect_uri"].as_str().unwrap().to_owned();
    let config = read("access-fapi2.json");
    for k in ["client", "client2"] {
        let keys: Vec<Value> = config[k]["jwks"]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| {
                let mut public = key.clone();
                public.as_object_mut().unwrap().remove("d");
                public
            })
            .collect();
        out.push((
            config[k]["client_id"].as_str().unwrap().to_owned(),
            String::from("private_key_jwt"),
            serde_json::json!({ "keys": keys }).to_string(),
            vec![fapi_redirect.clone()],
        ));
    }
    out
}

/// `GET {issuer}/login?return_to=…`: a new session for the realm's user, then back to the
/// stored request (TN-104: only to this realm's `/authorize`).
async fn sign_in(State(c): State<Arc<Cluster>>, RawQuery(q): RawQuery) -> Response {
    let at = c.at(0);
    let Some(return_to) = q
        .as_deref()
        .and_then(|q| Params::parse(q).ok())
        .and_then(|p| p.get("return_to").map(String::from))
        .filter(|r| return_to_ok(&at.f.realm.issuer, r))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let cookie = at.sign_in(now() - 1000).await;
    let set = format!("{SESSION_COOKIE}={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax");
    let to = format!("{}{return_to}", at.f.issuer);
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, HeaderValue::from_str(&set).unwrap()),
            (header::LOCATION, HeaderValue::from_str(&to).unwrap()),
        ],
    )
        .into_response()
}

async fn serve() {
    let listen = std::env::var("OIDF_LISTEN").unwrap_or_else(|_| String::from("0.0.0.0:9443"));
    let cluster = Arc::new(Cluster::seeded(BASE, &["acme"], &clients()).await);
    let discovery_url = read("access-oidcc.json")["server"]["discoveryUrl"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        discovery_url.starts_with(&cluster.realms[0].issuer),
        "{discovery_url} is not under {}",
        cluster.realms[0].issuer
    );
    let env = cluster.env();
    let routes = realm_router(Discovery::new(
        PgDirectory::new(env.router.clone()),
        SignerKeys::new(env.socket.clone()),
    ))
    .merge(oauth_router(OAuth::new(env)))
    .merge(
        Router::new()
            .route("/login", get(sign_in))
            .with_state(cluster.clone()),
    );
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![String::from(
        cluster.realms[0].host.split(':').next().unwrap(),
    )])
    .unwrap()
    .self_signed(&key)
    .unwrap();
    let tls = access_http::tls::server_config(
        cert.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
        None,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap();
    access_http::tls::serve(
        listener,
        tls,
        harden(routes, Limits::default()),
        std::future::pending(),
    )
    .await
    .unwrap();
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(serve());
}
