//! The OpenID Foundation conformance target (OP-146 I11, §14.8 SA-T2, B9, OP-155 m.3 (q)): one
//! realm `acme` seeded on the PostgreSQL at `DATABASE_URL` with the clients of every config in
//! `conformance/oidf/plans.json`, served over TLS 1.3 at `https://acme.id.test:9443` with the
//! realm, authorization server routes and a fixture sign-in page that starts a session for the
//! realm's one user. The realm has CIBA, front-channel logout, DCR behind an initial access token
//! and an OpenID Federation leaf that is its own trust anchor turned on. The nightly and release
//! workflows point the conformance suite and the differential tests at it.
//!
//! Client keys, client secrets and the initial access token that a config names as
//! `"$runtime:<name>"` are made here at start and written, with the private keys the suite signs
//! with, to the JSON file at `OIDF_RUNTIME`; the server certificate goes to `OIDF_CERT_OUT`.
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

use std::collections::BTreeMap;
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
use access_kernel::json::b64url_encode;
use access_store::client_profiles::ClientProfileRow;
use access_store::identity::TenantTx;
use aws_lc_rs::encoding::AsBigEndian as _;
use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rcgen::{CertificateParams, KeyPair};
use serde_json::{Value, json};
use support::{Cluster, Extra, ec_jwk, new_key, now};

/// The realm base of the target; the realm `acme` is `https://acme.id.test:9443`.
const BASE: &str = "https://id.test:9443";
/// What the suite's CIBA tests name the realm's user by.
const LOGIN_HINT: &str = "oidf-user";

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

/// The run-time values the configs name, made once.
#[derive(Default)]
struct Runtime(BTreeMap<String, Value>);

impl Runtime {
    fn name(v: &Value) -> Option<&str> {
        v.as_str().and_then(|s| s.strip_prefix("$runtime:"))
    }

    /// A random client secret for `"$runtime:<name>"`, or the literal secret.
    fn secret(&mut self, v: &Value) -> String {
        let Some(name) = Self::name(v) else {
            return v.as_str().unwrap().to_owned();
        };
        let bytes: [u8; 32] = access_crypto::random::bytes().unwrap();
        let s = b64url_encode(&bytes);
        self.0.insert(name.to_owned(), Value::from(s.clone()));
        s
    }

    /// The public JWKS of a fresh ES256 key for `"$runtime:<name>"` (its private JWKS is kept
    /// for the suite), or the literal JWKS without its private members.
    fn jwks(&mut self, v: &Value, kid: &str) -> String {
        let Some(name) = Self::name(v) else {
            let keys: Vec<Value> = v["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|key| {
                    let mut public = key.clone();
                    public.as_object_mut().unwrap().remove("d");
                    public
                })
                .collect();
            return json!({ "keys": keys }).to_string();
        };
        let key = new_key();
        let mut public: Value = serde_json::from_str(&ec_jwk(&key)).unwrap();
        public["kid"] = Value::from(kid);
        public["alg"] = Value::from("ES256");
        public["use"] = Value::from("sig");
        let mut private = public.clone();
        private["d"] = Value::from(b64url_encode(
            key.private_key().as_be_bytes().unwrap().as_ref(),
        ));
        self.0.insert(name.to_owned(), json!({ "keys": [private] }));
        json!({ "keys": [public] }).to_string()
    }
}

/// The suite's clients of every config: `client_secret_basic` where a config gives a secret,
/// `private_key_jwt` where it gives a JWKS, each redirecting to its plan's callback; the
/// second client also to the callback with the query the FAPI 2.0 plans add to it.
fn clients(rt: &mut Runtime) -> Vec<Extra> {
    let plans = read("plans.json");
    let default_redirect = plans["redirect_uri"].as_str().unwrap().to_owned();
    let mut configs: Vec<(String, String)> = Vec::new();
    for p in plans["plans"].as_array().unwrap() {
        let config = p["config"].as_str().unwrap().to_owned();
        let redirect = p["redirect_uri"]
            .as_str()
            .map_or_else(|| default_redirect.clone(), str::to_owned);
        if !configs.iter().any(|(c, _)| *c == config) {
            configs.push((config, redirect));
        }
    }
    let mut out = Vec::new();
    for (name, redirect) in configs {
        let config = read(&name);
        for k in ["client", "client2"] {
            let c = &config[k];
            let Some(id) = c["client_id"].as_str() else {
                continue;
            };
            let (method, secret) = if c.get("client_secret").is_some() {
                (
                    String::from("client_secret_basic"),
                    rt.secret(&c["client_secret"]),
                )
            } else {
                (
                    String::from("private_key_jwt"),
                    rt.jwks(&c["jwks"], &format!("{id}-1")),
                )
            };
            let mut redirects = vec![redirect.clone()];
            if k == "client2" {
                redirects.push(format!("{redirect}?dummy1=lorem&dummy2=ipsum"));
            }
            out.push((id.to_owned(), method, secret, redirects));
        }
    }
    out
}

/// The internal id of extra client `id` of the realm (`Cluster::seeded` numbers them after the
/// three fixture clients).
fn extra_uuid(extra: &[Extra], id: &str) -> [u8; 16] {
    let k = u8::try_from(extra.iter().position(|e| e.0 == id).unwrap() + 4).unwrap();
    [40, k, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, k]
}

/// Gives the two clients of `config` the profile `row`.
async fn profiles(cluster: &Cluster, extra: &[Extra], config: &str, row: &ClientProfileRow) {
    let at = cluster.at(0);
    let config = read(config);
    for k in ["client", "client2"] {
        let id = config[k]["client_id"].as_str().unwrap();
        let mut tx = TenantTx::begin(&cluster.db.app, at.f.realm.tenant, at.f.realm.realm)
            .await
            .unwrap();
        let b = at.bound(&mut tx, "idp.client.update").await;
        access_store::client_profiles::put_profile(&mut tx, &b, extra_uuid(extra, id), row)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
}

/// Turns on what the profile plans test, each under a spare ALLOW of its own action.
async fn configure(cluster: &Cluster, extra: &[Extra], rt: &mut Runtime) {
    let at = cluster.at(0);
    let suite = read("plans.json")["redirect_uri"]
        .as_str()
        .unwrap()
        .split("/test/a/")
        .next()
        .unwrap()
        .to_owned();
    let realm = (at.f.realm.tenant, at.f.realm.realm);
    let begin = || TenantTx::begin(&cluster.db.app, realm.0, realm.1);

    // IDP-24, OP-155 m.3 (k)
    at.enable_frontchannel().await;
    let row = ClientProfileRow {
        frontchannel_logout_uri: Some(format!("{suite}/test/a/access-logout/frontchannel_logout")),
        ..ClientProfileRow::default()
    };
    profiles(cluster, extra, "access-logout.json", &row).await;

    // OP-155 m.3 (k)
    let row = ClientProfileRow {
        fapi2: true,
        ..ClientProfileRow::default()
    };
    for config in ["access-fapi2.json", "access-fapi2-ms.json"] {
        profiles(cluster, extra, config, &row).await;
    }

    // OP-155 m.3 (l)
    let ciba = read("access-ciba.json");
    let ping: Vec<([u8; 16], String)> = ["client", "client2"]
        .iter()
        .map(|k| {
            (
                extra_uuid(extra, ciba[k]["client_id"].as_str().unwrap()),
                format!("{suite}/test/a/access-ciba/ciba-notification-endpoint"),
            )
        })
        .collect();
    let mut tx = begin().await.unwrap();
    let b = at.bound(&mut tx, "idp.realm.ciba").await;
    tx.put_ciba(
        &b,
        &access_store::ciba::CibaSettingsRow {
            enabled: true,
            login_hint: true,
            ping,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    rt.0.insert(String::from("login_hint"), Value::from(LOGIN_HINT));

    // OP-154 m.3 (j)
    let token = rt.secret(&Value::from("$runtime:dcr_iat"));
    let mut tx = begin().await.unwrap();
    let b = at.bound(&mut tx, "idp.client.dcr_policy").await;
    tx.put_dcr_policy(
        &b,
        &access_store::dcr::DcrPolicyRow {
            enabled: true,
            domains: vec![String::from("localhost.emobix.co.uk")],
            tokens: vec![suiss_crypto::digest::sha256(token.as_bytes())],
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // OP-155 m.3 (j), IDP-19
    let mut tx = begin().await.unwrap();
    let b = at.bound(&mut tx, "idp.federation.enable").await;
    tx.put_federation_settings(
        &b,
        &access_store::oidf::FederationSettingsRow {
            enabled: true,
            ta_enabled: true,
            registration_open: true,
            ..access_store::oidf::FederationSettingsRow::default()
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
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
    let mut rt = Runtime::default();
    let extra = clients(&mut rt);
    let cluster = Arc::new(Cluster::seeded(BASE, &["acme"], &extra).await);
    configure(&cluster, &extra, &mut rt).await;
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
        PgDirectory::new(env.router.clone()).with_facts(env.pool.clone()),
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
    if let Some(path) = std::env::var_os("OIDF_CERT_OUT") {
        std::fs::write(path, cert.pem()).unwrap();
    }
    if let Some(path) = std::env::var_os("OIDF_RUNTIME") {
        std::fs::write(path, serde_json::to_vec_pretty(&rt.0).unwrap()).unwrap();
    }
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
