//! Forward-auth on the real server path (IDP-30 (1), (3), B22, OP-156 m.3 (l), OP-153 m.3
//! (gg)): a proxy registered by a committed `idp.proxy.register` asks `/proxy/v1/check/{engine}`
//! through the real forward-auth router with its transport identity; the browser signs in at
//! the realm's real `/authorize` with its login session and code + PKCE; each request is the
//! authority core's eligibility check on the real sequencer and `SoftHSM`; the application token
//! is signed by the real identity signer and verified by the SDK against the realm JWKS.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one walk through forward-auth's rules"
)]

use std::time::Duration;

use access_http::tls::MtlsChain;
use access_identity_admin::domain::{AuthMethod, Change, RedirectUri};
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::oauth::PgOAuth;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::ports::Keys as _;
use access_identity_proxy::app::Proxy;
use access_identity_proxy::domain::engine::Engine;
use access_identity_proxy::domain::registration::{ProxyChange, Registration};
use access_sdk::resource::app_token::{
    APP_SKEW_MS, AppTokenError, AppTokenRules, app_token_algorithms, verify_app_token,
};
use access_store::identity::TenantTx;
use axum::body::Body;
use axum::http::{Request as HttpRequest, Response, StatusCode, header};

use super::management::send;
use super::vault::{Lab, revoke_grant};
use super::*;

const HOST: &str = "access.test";
const APP: &str = "wiki.example.com";
const CALLBACK: &str = "https://wiki.example.com/access-proxy/v1/callback";

type Env = crate::oauth::ServerEnv<TestPlane>;
type Forward =
    Proxy<crate::proxy::ServerPorts<Env, KeyStore, ActorBindings, OsSalts, SourcesClock>>;

fn oauth(w: &World) -> Arc<OAuth<Env>> {
    Arc::new(OAuth::new(crate::oauth::ServerEnv {
        saml: Arc::new(access_identity_oauth::ports::profile::NoSamlAssertions),
        client_certificates: Arc::new(access_identity_oauth::ports::profile::NoClientCertificates),
        db: PgOAuth::with_reader(w.db.app.clone(), w.db.reader.clone()),
        signer: SignerKeys::new(w.identity_signer.clone()),
        client_keys: HttpClientKeys::new(
            Outbound::disabled(Duration::from_secs(5)),
            CachePolicy::default(),
        ),
        documents: access_identity_oauth::adapters::cimd::HttpClientDocuments::new(
            Outbound::disabled(Duration::from_secs(5)),
        ),
        directory: access_identity_oauth::adapters::PgDirectory::new(w.db.router.clone()),
        app: w.db.app.clone(),
        nonces: crate::oauth::HsmNonces::new(w.keys.clone()),
        dpop: DpopProfile::default(),
        projections: w.plane.clone(),
        issuers: Arc::new(w.plane.clone()),
        bundles: Arc::new(access_identity_attest::ports::NoBundles),
        workload_trust: Arc::new(w.plane.clone()),
        standing: Arc::new(w.plane.clone()),
        tenant_ids: Arc::new(crate::ids::CellIds::new(w.keys.clone())),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        management: Arc::new(crate::admin::tokens::PlaneHolders(w.plane.clone(), None)),
        claims: Arc::new(access_identity_oauth::ports::oauth::NoClaims),
        ciba: Arc::new(access_identity_oauth::ports::oauth::NoCiba),
        geo: Arc::new(access_identity_oauth::ports::oauth::NoGeo),
    }))
}

/// Commits `change` as the realm's root through the identity plane's write path.
async fn commit(l: &Lab, change: Change) {
    let declared = DeclaredTargets::default();
    let b = Bootstrap {
        app: &l.w.db.app,
        router: &l.w.db.router,
        plane: &l.w.plane,
        realm_keys: &l.w.keyring,
        hsm: &l.w.keys,
        base: &l.w.base,
        declared: &declared,
        console: None,
    };
    let ids = cell_ids(&l.w.db.app, &l.w.keys).await.unwrap();
    b.change(
        &b.admin(&ids, None),
        (l.route.tenant, l.route.realm),
        l.domain,
        &root_key(&l.w.keys).unwrap(),
        change,
    )
    .await
    .unwrap();
}

/// A public client whose redirect URI is the application host's callback.
async fn proxy_client(l: &Lab) -> String {
    let declared = DeclaredTargets::default();
    let b = Bootstrap {
        app: &l.w.db.app,
        router: &l.w.db.router,
        plane: &l.w.plane,
        realm_keys: &l.w.keyring,
        hsm: &l.w.keys,
        base: &l.w.base,
        declared: &declared,
        console: None,
    };
    let ids = cell_ids(&l.w.db.app, &l.w.keys).await.unwrap();
    let id = b.admin(&ids, None).new_client_id().await.unwrap();
    commit(
        l,
        Change::ClientRegister(access_identity_admin::domain::Client {
            id: id.clone(),
            display_name: String::from("Wiki"),
            auth: AuthMethod::None,
            redirect_uris: vec![RedirectUri::parse(CALLBACK).unwrap()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            platform: None,
            subject: access_identity_admin::domain::Subject::default(),
            third_party: false,
        }),
    )
    .await;
    String::from(id.as_str())
}

/// The person's login session at the realm, as a sign-in leaves it: its cookie value.
async fn login_session(l: &Lab) -> String {
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now_ms();
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    let epoch = t
        .subject(l.subject, false)
        .await
        .unwrap()
        .unwrap()
        .session_epoch;
    t.insert_session(&access_store::sessions::NewSession {
        cookie_hash: &access_identity_session::domain::session::cookie_digest(&value),
        subject: l.subject,
        session_epoch: epoch,
        keep_signed_in: false,
        created_ms: i64::try_from(at).unwrap(),
        auth_time_ms: i64::try_from(at).unwrap(),
        idle_ms: 3_600_000,
        expires_ms: i64::try_from(at + 3_600_000).unwrap(),
        assurance: &serde_json::to_vec(&access_identity_session::domain::assurance::vector(&[
            access_identity_session::domain::assurance::Factor::password(at),
        ]))
        .unwrap(),
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    b64url_encode(&value)
}

struct Ask<'a> {
    engine: Engine,
    method: &'a str,
    uri: &'a str,
    cookie: Option<&'a str>,
    leaf: &'a [u8],
    extra: &'a [(&'a str, &'a str)],
}

/// One forward-auth check as `engine` sends it, from the proxy whose certificate is `leaf`.
async fn check(router: &axum::Router, a: &Ask<'_>) -> (Response<Body>, serde_json::Value) {
    let mut b = match a.engine {
        Engine::Envoy => HttpRequest::builder()
            .method(a.method)
            .uri(format!("/proxy/v1/check/envoy{}", a.uri))
            .header(header::HOST, APP),
        Engine::Nginx => HttpRequest::get("/proxy/v1/check/nginx")
            .header(header::HOST, HOST)
            .header("x-original-method", a.method)
            .header("x-original-uri", a.uri)
            .header("x-forwarded-host", APP),
        e => HttpRequest::get(format!("/proxy/v1/check/{}", e.word()))
            .header(header::HOST, HOST)
            .header("x-forwarded-method", a.method)
            .header("x-forwarded-uri", a.uri)
            .header("x-forwarded-host", APP),
    };
    if let Some(c) = a.cookie {
        b = b.header(header::COOKIE, c);
    }
    for (k, v) in a.extra {
        b = b.header(*k, *v);
    }
    let mut req = b.body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(MtlsChain(Arc::from(vec![a.leaf.to_vec()])));
    let (r, bytes) = send(router, req).await;
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (r, json)
}

fn header_of(r: &Response<Body>, name: &str) -> Option<String> {
    r.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_owned())
}

fn set_cookies(r: &Response<Body>) -> Vec<(String, String)> {
    r.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|c| {
            let (k, v) = c
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .split_once('=')
                .unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

fn path_of(url: &str) -> String {
    let rest = url.strip_prefix("https://").unwrap();
    rest[rest.find('/').unwrap()..].to_owned()
}

// IDP-30 (1), (3), B22, OP-156 m.3 (l), MD-8, TI-9, Ek B 5202, 5204
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registered_proxy_signs_the_browser_in_and_every_request_is_a_real_decision() {
    let l = Lab::open("walk-forward-auth").await;
    let client = proxy_client(&l).await;
    let leaf: [u8; 48] = access_crypto::random::bytes().unwrap();
    let pep = b64url_encode(&suiss_crypto::digest::sha256(&leaf));
    let registration = Registration {
        name: String::from("wiki"),
        engine: Engine::Traefik,
        host: String::from(APP),
        upstream: Some(String::from("http://10.0.0.5:8080")),
        client_id: client.clone(),
        pep: pep.clone(),
        action: l.action.clone(),
        namespace: String::from("work"),
        routes: vec![String::from("/")],
    };
    commit(&l, Change::Proxy(ProxyChange::Register(registration))).await;
    // OP-156 m.3 (l)
    assert!(l.w.domains.derive().await.is_empty());

    let service = oauth(&l.w);
    let proxy: Arc<Forward> = Arc::new(Proxy::new(crate::proxy::ServerPorts {
        router: l.w.db.router.clone(),
        app: l.w.db.app.clone(),
        oauth: service.clone(),
        domains: l.w.domains.clone(),
    }));
    let forward = access_http::harden(
        access_http::proxy::router(proxy.clone()),
        access_http::Limits::default(),
    );
    let authorize = access_http::oauth::shared_router(service.clone());
    let ask = |engine, method, uri, cookie| Ask {
        engine,
        method,
        uri,
        cookie,
        leaf: &leaf,
        extra: &[],
    };

    // IDP-30, B22
    let other: [u8; 48] = access_crypto::random::bytes().unwrap();
    let (r, body) = check(
        &forward,
        &Ask {
            leaf: &other,
            ..ask(Engine::Traefik, "GET", "/page", None)
        },
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "proxy-unregistered");

    // OP-156 m.3 (l)
    let (r, _) = check(&forward, &ask(Engine::Traefik, "GET", "/page?x=1", None)).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    let to = header_of(&r, "location").unwrap();
    assert!(
        to.starts_with("https://access.test/realms/acme/authorize?response_type=code&"),
        "{to}"
    );
    assert!(to.contains("code_challenge_method=S256"));
    let state = set_cookies(&r)
        .into_iter()
        .find(|(k, _)| k == "__Host-access-proxy-state")
        .unwrap()
        .1;
    let (r, _) = check(&forward, &ask(Engine::Nginx, "GET", "/page", None)).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "Nginx reads a 401");
    assert!(header_of(&r, "location").is_some());

    let session = login_session(&l).await;
    let (r, body) = send(
        &authorize,
        HttpRequest::get(path_of(&to))
            .header(header::HOST, HOST)
            .header(header::COOKIE, format!("__Host-access-session={session}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::SEE_OTHER,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let back = header_of(&r, "location").unwrap();
    assert!(back.starts_with(CALLBACK), "{back}");
    let callback = path_of(&back);

    // OP-156 m.3 (l), RFC 6749
    let (r, _) = check(
        &forward,
        &ask(
            Engine::Traefik,
            "GET",
            &callback,
            Some("__Host-access-proxy-state=forged"),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let state_cookie = format!("__Host-access-proxy-state={state}");
    let (r, _) = check(
        &forward,
        &ask(Engine::Traefik, "GET", &callback, Some(&state_cookie)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FOUND);
    assert_eq!(
        header_of(&r, "location").as_deref(),
        Some("https://wiki.example.com/page?x=1")
    );
    let proxy_cookie = set_cookies(&r)
        .into_iter()
        .find(|(k, _)| k == "__Host-access-proxy")
        .map(|(k, v)| format!("{k}={v}"))
        .unwrap();
    let (r, _) = check(
        &forward,
        &ask(Engine::Traefik, "GET", &callback, Some(&state_cookie)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "a code is redeemed once");

    // IDP-30 (1), (3)
    let spoofed = Ask {
        extra: &[("x-access-user", "admin"), ("access-identity", "forged")],
        ..ask(Engine::Traefik, "GET", "/page", Some(&proxy_cookie))
    };
    let (r, body) = check(&forward, &spoofed).await;
    assert_eq!(r.status(), StatusCode::OK, "{body}");
    assert_eq!(body["outcome"], "allow");
    assert!(body["ttl_s"].as_u64().unwrap() <= 30);
    let token = header_of(&r, "access-identity").unwrap();
    assert_ne!(token, "forged");
    assert_eq!(
        header_of(&r, "x-access-user"),
        None,
        "plain headers are off"
    );
    let jwks = SignerKeys::new(l.w.identity_signer.clone())
        .jwks(l.route.realm)
        .await
        .unwrap();
    let keys =
        access_sdk::resource::keys::key_set(jwks.as_bytes(), &app_token_algorithms()).unwrap();
    let rules = |aud| AppTokenRules {
        issuer: "https://access.test/realms/acme",
        audience: aud,
        now: now_ms(),
        skew_ms: APP_SKEW_MS,
    };
    let id = verify_app_token(&token, &keys, &rules("https://wiki.example.com")).unwrap();
    assert_ne!(id.sub, b64url_encode(&l.subject), "pairwise");
    assert_eq!(id.decision, body["decision"].as_str().unwrap());
    assert_eq!(
        verify_app_token(&token, &keys, &rules("https://other.example.com")),
        Err(AppTokenError::Claims)
    );
    let (r, _) = check(
        &forward,
        &ask(Engine::Envoy, "DELETE", "/page/1", Some(&proxy_cookie)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        header_of(&r, "x-envoy-auth-headers-to-remove").as_deref(),
        Some("x-access-user,x-access-email")
    );

    // OP-156 m.3 (l)
    commit(
        &l,
        Change::Proxy(ProxyChange::PlainHeaders(String::from("wiki"))),
    )
    .await;
    assert!(proxy.sweep().await >= 1, "the change moved the head");
    let (r, plain) = check(&forward, &spoofed).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(header_of(&r, "x-access-user"), Some(id.sub.clone()));
    commit(
        &l,
        Change::Proxy(ProxyChange::PlainHeadersClose(String::from("wiki"))),
    )
    .await;
    assert!(proxy.sweep().await >= 1);
    let (r, body) = check(&forward, &spoofed).await;
    assert_eq!(header_of(&r, "x-access-user"), None);
    assert_ne!(body["decision"], plain["decision"]);

    // OP-156 m.3 (l)
    let (_, again) = check(
        &forward,
        &ask(Engine::Traefik, "GET", "/other", Some(&proxy_cookie)),
    )
    .await;
    assert_eq!(again["decision"], body["decision"]);
    for b in
        l.w.domains
            .proxy_bases(l.domain, l.party, &l.action)
            .await
            .unwrap()
    {
        let (ExerciseBasis::Holding(HoldingRef { grant, .. }) | ExerciseBasis::Public(grant)) = b.0
        else {
            continue;
        };
        revoke_grant(&l, grant).await;
    }
    let (r, _) = check(
        &forward,
        &ask(Engine::Traefik, "GET", "/page", Some(&proxy_cookie)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "cached for at most 30 s");
    assert!(l.w.domains.derive().await.is_empty());
    assert!(proxy.sweep().await >= 1);
    let (r, body) = check(
        &forward,
        &ask(Engine::Traefik, "GET", "/page", Some(&proxy_cookie)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["outcome"], "deny");
    assert_eq!(header_of(&r, "access-identity"), None);

    // MD-8, TI-9
    l.w.db.app.close().await;
    let (r, body) = check(
        &forward,
        &ask(Engine::Caddy, "POST", "/page", Some(&proxy_cookie)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(header_of(&r, "retry-after").is_some());
}
