//! Cross-tenant isolation over the HTTP API (§12.1.3 test 3, TN-23, OP-138): property tests
//! over the composed realm, authorization server and hosted login routes of two realms in two
//! tenants on a real PostgreSQL. Whatever a request carries, the answer is never a server
//! error, never names or returns the other realm's data, never redirects anywhere but a
//! registered URI or the realm itself, and every authorization server answer is `no-store`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unused_async_trait_impl,
    clippy::type_complexity,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../../identity-oauth/tests/support/mod.rs"]
mod support;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_crypto::webauthn::DecoyKey;
use access_http::login::{Peer, router as login_router};
use access_http::oauth::router as oauth_router;
use access_http::realm::router as realm_router;
use access_http::{Limits, harden};
use access_identity_account::adapters::system::SystemClock;
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::ports::{RealmEntry, Unavailable};
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::adapters::Outbox;
use access_identity_ui::app::Hosted;
use access_identity_ui::ports::{Kits, RealmKit};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_store::identity::RealmId;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
use http_body_util::BodyExt;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use serde_json::Value;
use support::{BYE, CB, CHALLENGE, Cluster, NATIVE, VERIFIER, basic, claims};
use tower::ServiceExt;

struct Kit(HashMap<RealmId, Arc<RealmKit>>);

impl Kits for Kit {
    async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Unavailable> {
        self.0.get(&entry.realm).cloned().ok_or(Unavailable)
    }
}

fn kit(f: &support::Fixture, seed: u8) -> RealmKit {
    let wa = WaRealm::from_bytes(*f.realm.realm.as_bytes());
    RealmKit {
        tenant: f.realm.tenant,
        realm: f.realm.realm,
        issuer: f.issuer.clone(),
        name: f.slug.clone(),
        kek: Box::new(SoftKek::new("realm-kek:1", [seed; 32])),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        decoys: RealmDecoyKeys::default().with(wa, DecoyKey::new(Secret::new([seed; 32]))),
        rp: RelyingParty {
            realm: wa,
            rp_id: RpId::parse(&f.host).unwrap(),
            name: f.slug.clone(),
            pinned: true,
            related: Vec::new(),
        },
        webauthn: RealmPolicy::default(),
        auth: AuthPolicy::DEFAULT,
        lifetimes: SessionPolicy::DEFAULT,
    }
}

/// The routes `access-server` composes for the identity plane, hardened the same way.
fn app(c: &Cluster) -> Router {
    let env = c.env();
    let discovery = || {
        Discovery::new(
            PgDirectory::new(env.router.clone()),
            SignerKeys::new(env.socket.clone()),
        )
    };
    let kits = Kit(c
        .realms
        .iter()
        .enumerate()
        .map(|(i, f)| {
            (
                f.realm.realm,
                Arc::new(kit(f, 60 + u8::try_from(i).unwrap())),
            )
        })
        .collect());
    let hosted = Hosted {
        kits,
        db: env.pool.clone(),
        products: c.db.reader.clone(),
        clock: SystemClock,
        messages: Outbox,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 2, None)),
        redirect_to: String::from("/"),
        hooks: std::sync::Arc::new(access_identity_hooks::ports::NoHooks),
    };
    let routes = realm_router(discovery())
        .merge(oauth_router(OAuth::new(env.clone())))
        .merge(login_router(discovery(), hosted, None));
    harden(routes, Limits::default())
}

/// What the other realm minted, and what must never appear in this realm's answers unless
/// the request carried it.
struct Secrets {
    issuer: String,
    host: String,
    slug: String,
    clients: [String; 3],
    access: String,
    refresh: String,
    id_token: String,
    sub: String,
    cookie: String,
}

async fn secrets(c: &Cluster, i: usize) -> Secrets {
    let at = c.at(i);
    let t = at.tokens().await;
    let access = t["access_token"].as_str().unwrap().to_owned();
    Secrets {
        issuer: at.f.issuer.clone(),
        host: at.f.host.clone(),
        slug: at.f.slug.clone(),
        clients: [
            at.f.public.clone(),
            at.f.confidential.clone(),
            at.f.keyed.clone(),
        ],
        sub: claims(&access)["sub"].as_str().unwrap().to_owned(),
        refresh: t["refresh_token"].as_str().unwrap().to_owned(),
        id_token: t["id_token"].as_str().unwrap().to_owned(),
        access,
        cookie: at.f.cookie.clone(),
    }
}

impl Secrets {
    fn values(&self) -> Vec<&str> {
        let mut v = vec![
            self.issuer.as_str(),
            self.host.as_str(),
            self.slug.as_str(),
            self.access.as_str(),
            self.refresh.as_str(),
            self.id_token.as_str(),
            self.sub.as_str(),
            self.cookie.as_str(),
        ];
        v.extend(self.clients.iter().map(String::as_str));
        v
    }
}

/// A generated request.
#[derive(Clone, Debug)]
struct Gen {
    method: &'static str,
    host: usize,
    path: usize,
    slug: usize,
    content_type: usize,
    pairs: Vec<(usize, usize)>,
    json: bool,
    authorization: usize,
    cookie: usize,
    dpop: bool,
    idempotency: Option<u16>,
    template: usize,
    chaos: bool,
}

const PATHS: [&str; 20] = [
    "/authorize",
    "/token",
    "/par",
    "/userinfo",
    "/revoke",
    "/introspect",
    "/end-session",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/jwks.json",
    "/v1/login/flows",
    "/v1/login/flows/lgf_0000",
    "/v1/login/link/preview",
    "/v1/sessions/current",
    "/v1/sessions",
    "/v1/sessions/current/sign-out",
    "/v1/account/totp",
    "/check_session_iframe",
    "/login",
];

const KEYS: [&str; 22] = [
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "code_challenge",
    "code_challenge_method",
    "state",
    "nonce",
    "grant_type",
    "code",
    "code_verifier",
    "refresh_token",
    "token",
    "request_uri",
    "prompt",
    "id_token_hint",
    "post_logout_redirect_uri",
    "client_assertion_type",
    "client_assertion",
    "dpop_jkt",
    "resource",
    "token_type_hint",
];

/// Values a request can carry: the realm's own and the other realm's identifiers and tokens,
/// protocol words and junk. Indexes 0..`OWN` are filled per realm at run time.
const OWN: usize = 7;
const WORDS: [&str; 20] = [
    CB,
    NATIVE,
    BYE,
    "https://evil.example/cb",
    "code",
    "token",
    "openid",
    "S256",
    "plain",
    "none",
    "login",
    "authorization_code",
    "refresh_token",
    "password",
    CHALLENGE,
    VERIFIER,
    "urn:ietf:params:oauth:request_uri:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "%zz",
    "\u{0}\u{7f}ü",
    "",
];

fn strategy() -> impl Strategy<Value = Gen> {
    (
        (
            prop_oneof![4 => Just("GET"), 4 => Just("POST"), 1 => Just("PUT"), 1 => Just("DELETE")],
            prop_oneof![4 => 0..2_usize, 1 => 2..6_usize],
            0..PATHS.len(),
            prop_oneof![4 => Just(0_usize), 1 => 1..4_usize],
            prop_oneof![4 => Just(0_usize), 1 => 1..4_usize],
            prop::collection::vec((0..KEYS.len(), 0..(2 * OWN + WORDS.len() + 1)), 0..6),
        ),
        (
            any::<bool>(),
            0..6_usize,
            0..5_usize,
            any::<bool>(),
            prop::option::of(any::<u16>()),
            0..5_usize,
            prop::bool::weighted(0.2),
        ),
    )
        .prop_map(
            |(
                (method, host, path, slug, content_type, pairs),
                (json, authorization, cookie, dpop, idempotency, template, chaos),
            )| Gen {
                method,
                host,
                path,
                slug,
                content_type,
                pairs,
                json,
                authorization,
                cookie,
                dpop,
                idempotency,
                template,
                chaos,
            },
        )
}

/// A well-formed starting request per template: (method, path, JSON body, pairs).
fn template(t: usize) -> Option<(&'static str, usize, bool, Vec<(usize, usize)>)> {
    let w = |i: usize| 2 * OWN + i;
    match t {
        1 => Some((
            "GET",
            0,
            false,
            vec![
                (0, 0),
                (1, w(0)),
                (2, w(4)),
                (3, w(6)),
                (4, w(14)),
                (5, w(7)),
                (6, w(4)),
            ],
        )),
        2 => Some(("POST", 1, false, vec![(8, w(12)), (0, 0), (11, 4)])),
        3 => Some(("POST", 5, false, vec![(12, 3)])),
        4 => Some(("POST", 11, true, vec![])),
        _ => None,
    }
}

struct World {
    c: Cluster,
    app: Router,
    secrets: [Secrets; 2],
    seen: std::sync::Mutex<std::collections::BTreeMap<u16, u32>>,
}

fn form_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

impl World {
    /// The value at `i`: the target realm's own values, then the other realm's, then words.
    fn value(&self, own: usize, i: usize) -> String {
        let pick = |s: &Secrets, k: usize| match k {
            0 => s.clients[0].clone(),
            1 => s.clients[1].clone(),
            2 => s.clients[2].clone(),
            3 => s.access.clone(),
            4 => s.refresh.clone(),
            5 => s.id_token.clone(),
            _ => s.cookie.clone(),
        };
        if i < OWN {
            pick(&self.secrets[own], i)
        } else if i < 2 * OWN {
            pick(&self.secrets[1 - own], i - OWN)
        } else if let Some(w) = WORDS.get(i - 2 * OWN) {
            (*w).to_owned()
        } else {
            "x".repeat(5000)
        }
    }

    async fn run(&self, g: &Gen) -> Result<(), TestCaseError> {
        let own = g.host % 2;
        let hosts = [
            self.secrets[0].host.clone(),
            self.secrets[1].host.clone(),
            self.secrets[0].host.to_uppercase(),
            format!("{}:8443", self.secrets[1].host),
            String::from("id.test"),
            String::from("evil.test"),
        ];
        let host = &hosts[g.host];
        let (method, path_index, json, base) = match template(g.template) {
            Some((m, p, j, base)) if !g.chaos => (m, p, j, base),
            _ => (g.method, g.path, g.json, Vec::new()),
        };
        let slug = [
            None,
            Some(self.secrets[0].slug.as_str()),
            Some(self.secrets[1].slug.as_str()),
            Some("nope"),
        ][g.slug];
        let path = match slug {
            Some(s) => format!("/realms/{s}{}", PATHS[path_index]),
            None => String::from(PATHS[path_index]),
        };
        let mut chosen = base;
        for (k, v) in &g.pairs {
            chosen.retain(|(bk, _)| bk != k);
            chosen.push((*k, *v));
        }
        let pairs: Vec<(String, String)> = chosen
            .iter()
            .map(|(k, v)| (KEYS[*k].to_owned(), self.value(own, *v)))
            .collect();
        let form: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{k}={}", form_encode(v)))
            .collect();
        let form = form.join("&");
        let uri = if method == "GET" && !form.is_empty() {
            format!("{path}?{form}")
        } else {
            path.clone()
        };
        let mut req = Request::builder()
            .method(method)
            .uri(&uri)
            .header(header::HOST, host);
        let content_type = [
            Some("application/x-www-form-urlencoded"),
            Some("application/json"),
            Some("text/plain"),
            None,
        ][g.content_type];
        if let Some(ct) = content_type {
            req = req.header(header::CONTENT_TYPE, ct);
        }
        let s = &self.secrets;
        let authorization = [
            None,
            Some(basic(&s[own].clients[1], "x")),
            Some(basic(&s[1 - own].clients[1], "x")),
            Some(format!("DPoP {}", s[own].access)),
            Some(format!("DPoP {}", s[1 - own].access)),
            Some(String::from("Basic !!!")),
        ][g.authorization]
            .clone();
        if let Some(a) = &authorization {
            req = req.header(header::AUTHORIZATION, a);
        }
        let cookie = [
            None,
            Some(format!("__Host-access-session={}", s[own].cookie)),
            Some(format!("__Host-access-session={}", s[1 - own].cookie)),
            Some(format!(
                "__Host-access-session={}; __Host-access-session={}",
                s[0].cookie, s[1].cookie
            )),
            Some(String::from("__Host-access-session=%%%")),
        ][g.cookie]
            .clone();
        if let Some(c) = &cookie {
            req = req.header(header::COOKIE, c);
        }
        if g.dpop {
            let a = self.c.at(own);
            let proof = a.proof("POST", &format!("{}/token", a.f.issuer), None);
            req = req.header("dpop", proof);
        }
        if let Some(k) = g.idempotency {
            req = req.header("idempotency-key", format!("k-{k}"));
        }
        let body = if method == "GET" {
            Body::empty()
        } else if json {
            let m: serde_json::Map<String, Value> = pairs
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
                .collect();
            Body::from(Value::Object(m).to_string())
        } else {
            Body::from(form.clone())
        };
        let mut req = req.body(body).unwrap();
        req.extensions_mut()
            .insert(Peer(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))));
        let sent = format!("{uri} {form} {authorization:?} {cookie:?}");
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status().as_u16();
        *self.seen.lock().unwrap().entry(status).or_default() += 1;
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = format!(
            "{} {}",
            headers
                .iter()
                .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join("\n"),
            String::from_utf8_lossy(&bytes)
        );
        // G50, SA-21, R-3
        prop_assert!(status < 500, "{status} for {g:?}: {text}");
        // TN-23, MD-5, TN-2, X41
        let resolved = match (g.host, slug) {
            (0 | 2, None) => Some(0),
            (1, None) => Some(1),
            _ => None,
        };
        let others: Vec<&str> = match resolved {
            Some(r) => s[1 - r].values(),
            None => s[0].values().into_iter().chain(s[1].values()).collect(),
        };
        for secret in others {
            if secret.len() >= 8 && text.contains(secret) {
                prop_assert!(sent.contains(secret), "{secret} leaked for {g:?}: {text}");
            }
        }
        // IDP-7, TN-104, must-never #16
        if let Some(to) = headers.get(header::LOCATION) {
            let to = to.to_str().unwrap();
            let allowed = [CB, NATIVE, BYE, "http://127.0.0.1"]
                .iter()
                .map(|u| (*u).to_owned())
                .chain(resolved.map(|r| s[r].issuer.clone()))
                .any(|prefix| {
                    to.starts_with(&format!("{prefix}?"))
                        || to.starts_with(&format!("{prefix}/"))
                        || to == prefix
                });
            prop_assert!(allowed || to.starts_with('/'), "redirect to {to} for {g:?}");
        }
        // §11.4.5, RFC 6749 §5.1
        let oauth =
            ["/token", "/par", "/userinfo", "/revoke", "/introspect"].contains(&PATHS[path_index]);
        if oauth && resolved.is_some() && method == "POST" && status != 404 && status != 405 {
            prop_assert_eq!(
                headers
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store"),
                "{:?}",
                g
            );
        }
        Ok(())
    }
}

// TN-23, §12.1.3, OP-138, MD-5, TN-2, TN-7, G50, IDP-7, TN-104, X41, must-never #16: test 3 of
// the six cross-tenant isolation tests, over the HTTP API
#[test]
fn http_api_never_crosses_realms_or_fails() {
    // K05
    let rt = tokio::runtime::Runtime::new().unwrap();
    let world = rt.block_on(async {
        let c = Cluster::new(&["prop-a", "prop-b"]).await;
        let app = app(&c);
        let secrets = [secrets(&c, 0).await, secrets(&c, 1).await];
        World {
            c,
            app,
            secrets,
            seen: std::sync::Mutex::default(),
        }
    });
    let config = Config {
        cases: 192,
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner =
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha));
    runner
        .run(&strategy(), |g| rt.block_on(world.run(&g)))
        .unwrap();
    let seen = world.seen.lock().unwrap();
    for status in [200, 201, 303, 400, 401, 404, 415] {
        assert!(seen.contains_key(&status), "no {status} among {seen:?}");
    }
}

// §10.4.6, IDP-24, OIDC Session Management (iframe) yok: no session management iframe or check
// session endpoint is routed, at the host root or under a path issuer
#[test]
fn no_session_management_iframe() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let c = Cluster::new(&["nsm-a"]).await;
        let app = app(&c);
        let host = c.realms[0].host.clone();
        for path in [
            "/check_session_iframe",
            "/check-session",
            "/session/check",
            "/op/check_session",
            "/realms/nsm-a/check_session_iframe",
        ] {
            let mut req = Request::get(path)
                .header(header::HOST, &host)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(Peer(IpAddr::V4(Ipv4Addr::LOCALHOST)));
            let r = app.clone().oneshot(req).await.unwrap();
            assert_eq!(r.status().as_u16(), 404, "{path}");
        }
    });
}
