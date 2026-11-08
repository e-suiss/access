//! The management surface end to end against the real sequencer (OP-151 m.2 M1b, m.12, Ek B
//! 3300): a bootstrapped realm with its console client, a user signed in at the realm's own
//! authorization server, the console's session and device Instance, a read through the BFF with
//! a read proof and a realm-issued, DPoP-bound read token, and a branding write that the BFF
//! passes on with the browser's AIS and that moves the domain's log.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use access_authority_core::genesis::IDP_ANCHOR;
use access_http::api::domain::SurfaceScope;
use access_http::api::domain::caller::{MAX_TOKEN_LIFETIME_MS, Refusal, check_read};
use access_http::api::ports::{Presented, ReadTokens as _};
use access_http::console::domain::read_intent;
use access_http::console::ports::DpopKeys as _;
use access_http::login::Peer;
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::oauth::PgOAuth;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::domain::request::Params;
use access_identity_session::domain::assurance::{Factor, vector};
use access_identity_session::domain::session::cookie_digest;
use access_internal_api::instances::cose_key;
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, kind};
use access_kernel::verify::key_scope::thumbprint;
use access_store::sessions::NewSession;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode, header};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};
use tower::ServiceExt as _;

use super::*;

const ORIGIN: &str = "https://manage.access.test:9443";
const HOST: &str = "access.test";
const SESSION: &str = "__Host-access-session";

fn now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

async fn send(router: &axum::Router, request: Request<Body>) -> (Response<Body>, Vec<u8>) {
    let r = router.clone().oneshot(request).await.unwrap();
    let (parts, body) = r.into_parts();
    let bytes = to_bytes(body, 1 << 22).await.unwrap().to_vec();
    (Response::from_parts(parts, Body::empty()), bytes)
}

fn location(r: &Response<Body>) -> String {
    r.headers()[header::LOCATION].to_str().unwrap().to_owned()
}

fn cookies(r: &Response<Body>) -> Vec<(String, String)> {
    r.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| {
            let (pair, _) = v.to_str().ok()?.split_once(';')?;
            let (k, v) = pair.split_once('=')?;
            Some((k.to_owned(), v.to_owned()))
        })
        .collect()
}

fn path_of(url: &str) -> String {
    let rest = url.strip_prefix("https://").unwrap();
    rest[rest.find('/').unwrap()..].to_owned()
}

/// The browser: its console cookies, CSRF token and device key.
struct Browser {
    jar: Vec<(String, String)>,
    csrf: String,
    key: SoftSigner,
}

impl Browser {
    fn request(&self, method: &Method, path: &str, body: &str) -> axum::http::request::Builder {
        let cookie = self
            .jar
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::COOKIE, cookie)
            .header("sec-fetch-site", "same-origin");
        if *method != Method::GET {
            b = b
                .header(header::ORIGIN, ORIGIN)
                .header("x-csrf-token", &self.csrf);
        }
        if !body.is_empty() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        b
    }

    fn ais(
        &self,
        domain: Digest,
        nonce: &[u8],
        intent: Digest,
        mode: Mode,
        basis: ExerciseBasis,
    ) -> String {
        self.ais_for(
            access_identity_ui::domain::frontend::IDENTITY_PEP,
            domain,
            nonce,
            intent,
            mode,
            basis,
        )
    }

    fn ais_for(
        &self,
        pep: &str,
        domain: Digest,
        nonce: &[u8],
        intent: Digest,
        mode: Mode,
        basis: ExerciseBasis,
    ) -> String {
        let s = Statement {
            domain,
            nonce: nonce.to_vec(),
            intent,
            mode,
            pep: String::from(pep),
            capacity: Capacity::Own,
            basis,
            iat: now(),
            exercise: None,
        };
        let payload = dcbor::encode(&s.to_value(), Limits::CEILING).unwrap();
        let kid = thumbprint(&self.key.public_key());
        b64url_encode(&sign_sign1(&self.key as &dyn Signer, kid, CONTENT_TYPE, &payload).unwrap())
    }
}

fn envelope_digest(b64: &str) -> Digest {
    let bytes = b64url_decode(b64).unwrap();
    let v = dcbor::decode(&bytes, Limits::CEILING).unwrap();
    intent_digest(&IntentEnvelope::from_value(&v).unwrap()).unwrap()
}

/// What a signed-in console with a registered browser Instance holds.
struct Console {
    w: World,
    management: axum::Router,
    browser: Browser,
    domain: Digest,
    root: access_kernel::model::Id,
    route: access_store::tenancy::RealmRoute,
    subject: [u8; 16],
}

/// A bootstrapped realm `acme` whose founder signed in to the console at the realm's own
/// authorization server and registered the browser's key as the session's device Instance; the
/// console's ADP proxy reaches the real decision point when `with_adp`.
async fn console(label: &str, with_adp: bool) -> Console {
    let w = World::new(label).await;
    let declared = DeclaredTargets::default();
    Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &declared,
        console: Some(ORIGIN),
    }
    .run(&plan())
    .await
    .unwrap();
    w.domains.release().await;
    crate::jobs::open_now(&w.db.app, &w.db.archive, label).await;
    let day = u32::try_from(now() / 86_400_000).unwrap();
    for d in [day - 1, day, day + 1] {
        access_store::dpop::open_dpop_replay_day(&w.db.archive, d)
            .await
            .unwrap();
    }

    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let root = root_party(&root_key(&w.keys).unwrap().public_key());
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let subject = t
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    assert!(
        idp::bind_subject_party(&mut t, &subject, &root.0)
            .await
            .unwrap()
    );
    let domain = Digest(
        *idp::governance(&mut t)
            .await
            .unwrap()
            .unwrap()
            .domain
            .as_bytes(),
    );
    t.commit().await.unwrap();

    let ids = Arc::new(crate::ids::CellIds::new(w.keys.clone()));
    let oauth = access_http::oauth::router(OAuth::new(crate::oauth::ServerEnv {
        db: PgOAuth::with_reader(w.db.app.clone(), w.db.reader.clone()),
        signer: SignerKeys::new(w.identity_signer.clone()),
        client_keys: HttpClientKeys::new(
            Outbound::disabled(Duration::from_secs(5)),
            CachePolicy::default(),
        ),
        directory: PgDirectory::new(w.db.router.clone()),
        app: w.db.app.clone(),
        nonces: crate::oauth::HsmNonces::new(w.keys.clone()),
        dpop: DpopProfile::default(),
        projections: w.plane.clone(),
        tenant_ids: Arc::clone(&ids),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        management: Arc::new(crate::admin::tokens::PlaneHolders(w.plane.clone(), None)),
    }));
    let management = crate::admin::router(
        (String::from(ORIGIN), w.identity_signer.clone()),
        &w.keys,
        crate::admin::realm::Realms {
            app: w.db.app.clone(),
            reads: w.db.app.clone(),
            checkpointer: w.db.checkpointer.clone(),
            router: w.db.router.clone(),
            ids: Arc::clone(&ids),
            plane: w.plane.clone(),
            base: w.base.clone(),
            keys: Arc::new(RealmKeyring::new(
                SignerKeys::new(w.identity_signer.clone()),
                w.keys.clone(),
            )),
            declared: DeclaredTargets::default(),
            platform: None,
            outbound: Outbound::disabled(Duration::from_secs(5)),
            vault: access_identity_events::adapters::KekSealer(crate::login::RealmKeks::new(
                w.keys.clone(),
            )),
            geo: std::sync::Arc::new(access_identity_risk::adapters::NoGeoSource),
            ips: std::sync::Arc::new(access_identity_risk::adapters::NoPseudonyms),
        },
        crate::admin::InProcessRoutes {
            oauth: oauth.clone(),
            adp: if with_adp {
                access_http::adp::adapters::router(
                    access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
                    access_http::adp::adapters::Discovery {
                        issuer: String::from("https://access.test"),
                    },
                )
            } else {
                axum::Router::new()
            },
        },
        None,
    )
    .unwrap()
    .layer(axum::Extension(Peer(IpAddr::V4(Ipv4Addr::new(
        10, 1, 2, 3,
    )))));

    // TN-131, OP-151 m.12 (b)
    let (r, _) = send(
        &management,
        Request::get("/console/api/sign-in?realm=acme")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let authorize = location(&r);
    let started = cookies(&r);
    assert!(authorize.starts_with("https://access.test/realms/acme/authorize?"));
    assert!(authorize.contains("prompt=login") && authorize.contains("code_challenge_method=S256"));
    let (r, _) = send(
        &oauth,
        Request::get(path_of(&authorize))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let login = location(&r);
    let return_to = Params::parse(login.split_once('?').unwrap().1)
        .unwrap()
        .get("return_to")
        .unwrap()
        .to_owned();
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    t.insert_session(&NewSession {
        cookie_hash: &cookie_digest(&value),
        subject,
        session_epoch: 0,
        keep_signed_in: false,
        created_ms: i64::try_from(at).unwrap(),
        auth_time_ms: i64::try_from(at).unwrap(),
        idle_ms: 3_600_000,
        expires_ms: i64::try_from(at + 3_600_000).unwrap(),
        assurance: &serde_json::to_vec(&vector(&[Factor::password(at)])).unwrap(),
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    let (r, body) = send(
        &oauth,
        Request::get(&return_to)
            .header(header::HOST, HOST)
            .header(
                header::COOKIE,
                format!("{SESSION}={}", b64url_encode(&value)),
            )
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
    let callback = location(&r);
    assert!(callback.starts_with(&format!("{ORIGIN}/console/api/sign-in/callback?")));

    // TN-128, TN-129
    let jar = started
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let (r, body) = send(
        &management,
        Request::get(callback.strip_prefix(ORIGIN).unwrap())
            .header(header::COOKIE, jar)
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
    let set = cookies(&r);
    let csrf = set
        .iter()
        .find(|(k, _)| k == "__Host-access-console-csrf")
        .unwrap()
        .1
        .clone();
    let browser = Browser {
        jar: set.into_iter().filter(|(_, v)| !v.is_empty()).collect(),
        csrf,
        key: SoftSigner::generate_p256().unwrap().0,
    };
    let (r, body) = send(
        &management,
        browser
            .request(&Method::GET, "/console/api/session", "")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["realm"], "acme");
    assert!(session["instance"].is_null());

    // OP-149 m.6, OP-151 m.3 (e)
    let key = b64url_encode(&cose_key(&browser.key.public_key()));
    let (r, body) = send(
        &management,
        browser
            .request(&Method::POST, "/console/api/instances/challenge", "x")
            .body(Body::from(serde_json::json!({ "key": key }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let c: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(c["party"], b64url_encode(&root.0));
    assert!(c.get("register").is_none());
    let grant = <[u8; 16]>::try_from(b64url_decode(c["basis"].as_str().unwrap()).unwrap()).unwrap();
    let challenge = b64url_decode(c["challenge"].as_str().unwrap()).unwrap();
    let create = browser.ais(
        domain,
        &challenge,
        envelope_digest(c["create"].as_str().unwrap()),
        Mode::Commit,
        ExerciseBasis::Public(access_kernel::model::Id(grant)),
    );
    let registration = serde_json::json!({
        "challenge": c["challenge"],
        "party": c["party"],
        "key": key,
        "valid_from": c["valid_from"],
        "valid_until": c["valid_until"],
        "ais": create,
    });
    let (r, body) = send(
        &management,
        browser
            .request(&Method::POST, "/console/api/instances", "x")
            .body(Body::from(registration.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );

    Console {
        w,
        management,
        browser,
        domain,
        root,
        route,
        subject,
    }
}

// OP-151 m.12 (b), (c), (e), TN-128, TN-129, TN-130, TN-110, TN-27, Ek B 3300
#[tokio::test]
async fn the_console_signs_in_reads_and_writes_through_the_sequencer() {
    let Console {
        w,
        management,
        mut browser,
        domain,
        route,
        subject,
        ..
    } = console("mgmt-e2e", false).await;
    // TN-128, TN-130
    let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
    let target = "/admin/v1/realms/acme/settings";
    let proof = browser.ais(
        domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::GET, target),
        Mode::Check,
        basis,
    );
    let (r, body) = send(
        &management,
        browser
            .request(
                &Method::GET,
                "/console/api/proxy/admin/realms/acme/settings",
                "",
            )
            .header("x-access-ais", proof)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let etag = r.headers()[header::ETAG].to_str().unwrap().to_owned();
    let settings: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(settings.get("branding").is_some());

    // §8.13, IDP-36, TN-136, OP-151 m.19 (e)
    let read = |target: &'static str| {
        let proof = browser.ais(
            domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::GET, target),
            Mode::Check,
            basis,
        );
        browser
            .request(
                &Method::GET,
                &target.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                "",
            )
            .header("x-access-ais", proof)
            .body(Body::empty())
            .unwrap()
    };
    let (r, body) = send(&management, read("/admin/v1/realms/acme/signals")).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let signals: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(signals["geoip"], "not_configured");
    assert_eq!(signals["transmitters"], serde_json::json!([]));
    assert_eq!(signals["verifiers"], serde_json::json!([]));
    let (r, body) = send(&management, read("/admin/v1/realms/acme/analytics")).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let analytics: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(analytics["days"].is_array() && analytics["surges"].is_array());
    let (r, _) = send(
        &management,
        read("/admin/v1/realms/acme/webhooks/whk_unknown/deliveries"),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // OP-151
    let (r, _) = send(
        &management,
        browser
            .request(
                &Method::GET,
                "/console/api/proxy/admin/realms/acme/settings",
                "",
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_ne!(r.status(), StatusCode::OK);

    // TN-110, OP-151 m.11 (a)
    let drafts = "/admin/v1/realms/acme/intents";
    let ask = serde_json::json!({
        "operation": "putBranding",
        "body": { "display_name": "Acme Admin" },
    })
    .to_string();
    let proof = browser.ais(
        domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, drafts),
        Mode::Check,
        basis,
    );
    let (r, body) = send(
        &management,
        browser
            .request(
                &Method::POST,
                "/console/api/proxy/admin/realms/acme/intents",
                "x",
            )
            .header("x-access-ais", proof)
            .body(Body::from(ask))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let draft: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let digest = Digest(
        <[u8; 32]>::try_from(b64url_decode(draft["intent_digest"].as_str().unwrap()).unwrap())
            .unwrap(),
    );
    let before = w.domains.head(domain).await.unwrap().0;
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let ais = browser.ais(domain, &nonce, digest, Mode::Commit, basis);
    let (r, body) = send(
        &management,
        browser
            .request(
                &Method::PUT,
                "/console/api/proxy/admin/realms/acme/settings/branding",
                "x",
            )
            .header("x-access-ais", ais)
            .header("idempotency-key", b64url_encode(&nonce))
            .header(header::IF_MATCH, etag)
            .body(Body::from(draft["body"].to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let written: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let position: u64 = written["position"].as_str().unwrap().parse().unwrap();
    assert!(position > before, "{position} > {before}");
    assert!(written["exercise_id"].is_string());

    // TN-130, TN-27, OP-21
    let tokens = crate::admin::tokens::ManagementTokens {
        directory: PgDirectory::new(w.db.router.clone()),
        signer: SignerKeys::new(w.identity_signer.clone()),
        app: w.db.app.clone(),
        plane: w.plane.clone(),
        dpop: DpopProfile::default(),
        platform: None,
    };
    let row = access_store::console::live_of(&w.db.app, route.tenant, route.realm, &subject, 10)
        .await
        .unwrap()
        .remove(0);
    let (kid, cose) = row.instance.clone().unwrap();
    let instance = access_http::console::ports::SessionInstance {
        kid,
        key: access_identity_session::domain::device::instance_key(&cose).unwrap(),
    };
    let dpop = crate::console::MemoryDpop::default();
    let issued = tokens
        .issue_console(&row, &instance, dpop.jkt(row.id).unwrap())
        .await
        .unwrap()
        .unwrap();
    let token = String::from_utf8(issued.token.expose().clone()).unwrap();
    let uri = format!("{ORIGIN}{target}");
    let ath = suiss_crypto::digest::sha256(token.as_bytes());
    let fresh = |session: [u8; 16]| dpop.proof(session, "GET", &uri, &ath, now()).unwrap();
    let presented = |proofs: &'static [&'static str]| Presented {
        token: Box::leak(token.clone().into_boxed_str()),
        proofs,
        method: "GET",
        uri: Box::leak(uri.clone().into_boxed_str()),
    };
    let leak = |p: String| -> &'static [&'static str] {
        Box::leak(vec![&*Box::leak(p.into_boxed_str())].into_boxed_slice())
    };
    let good = leak(fresh(row.id));
    let read = tokens.verify(presented(good)).await.unwrap().unwrap();
    assert_eq!(read.audience, "access-admin:realm:acme");
    assert_eq!(read.scopes, ["realm.read"]);
    assert!(read.expires_at_ms - read.issued_at_ms <= MAX_TOKEN_LIFETIME_MS);
    assert_eq!(
        check_read(
            &read,
            &SurfaceScope::Realm(String::from("platform")),
            "realm.read",
            now()
        ),
        Err(Refusal::WrongAudience)
    );
    assert!(
        tokens.verify(presented(&[])).await.unwrap().is_none(),
        "bearer"
    );
    assert!(
        tokens.verify(presented(good)).await.unwrap().is_none(),
        "replayed proof"
    );
    let other = leak(fresh([9; 16]));
    assert!(
        tokens.verify(presented(other)).await.unwrap().is_none(),
        "another key"
    );
    access_store::console::end(
        &w.db.app,
        &row.id,
        now(),
        access_store::console::EndReason::Revoked,
    )
    .await
    .unwrap();
    let after = leak(fresh(row.id));
    assert!(
        tokens.verify(presented(after)).await.unwrap().is_none(),
        "session ended"
    );
    browser.jar.clear();
}

// TN-110, TN-128, MD-14, OP-151 m.19 (a), (d), m.8 (b), Ek B 3088
#[tokio::test]
async fn a_console_commit_goes_to_adp_only_with_the_browsers_ais() {
    let Console {
        management,
        browser,
        domain,
        root,
        w,
        ..
    } = console("mgmt-commit", true).await;
    let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
    let ask = serde_json::json!({
        "action": { "namespace": "access", "name": "audit_export", "major": 1 },
        "resources": [{ "namespace": "access.audit", "path": ["acme"] }],
        "params": { "from": 0, "disclosure": "redacted" },
        "mode": "commit",
    })
    .to_string();
    let proof = browser.ais(
        domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, "/console/api/intents"),
        Mode::Check,
        basis,
    );
    let (r, body) = send(
        &management,
        browser
            .request(&Method::POST, "/console/api/intents", "x")
            .header("x-access-ais", proof)
            .body(Body::from(ask))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let draft: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let digest = envelope_digest(draft["envelope"].as_str().unwrap());
    // OP-141
    let auditor = ExerciseBasis::Anchor(meta::meta_anchor(&domain));
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let body_with = |ais: Option<String>| {
        let mut context = serde_json::json!({
            "domain": b64url_encode(&domain.0),
            "mode": "commit",
            "nonce": b64url_encode(&nonce),
            "intent": draft["intent"],
            "basis": { "anchor": b64url_encode(&meta::meta_anchor(&domain).0) },
            "capacity": "own",
        });
        if let Some(a) = ais {
            context["ais"] = serde_json::Value::String(a);
        }
        serde_json::json!({
            "subject": { "type": "access_party", "id": b64url_encode(&root.0) },
            "action": { "name": "audit_export" },
            "resource": { "type": "access.audit", "id": "acme" },
            "context": context,
        })
        .to_string()
    };
    let pep = crate::console::CONSOLE_PEP;
    let post = |path: &str, body: String| {
        browser
            .request(&Method::POST, path, "x")
            .body(Body::from(body))
            .unwrap()
    };
    let before = w.domains.head(domain).await.unwrap().0;
    let check = browser.ais_for(pep, domain, &nonce, digest, Mode::Check, auditor);
    for refused in [None, Some(check)] {
        let (r, body) = send(
            &management,
            post("/console/api/proxy/adp/evaluation", body_with(refused)),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let p: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(p["code"], "commit-ais-rejected");
    }
    assert_eq!(w.domains.head(domain).await.unwrap().0, before);
    let ais = browser.ais_for(pep, domain, &nonce, digest, Mode::Commit, auditor);
    let signed = body_with(Some(ais));
    let (r, body) = send(
        &management,
        post("/console/api/proxy/adp/evaluation", signed.clone()),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let decided: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(decided["decision"], true, "{decided}");
    assert!(decided["context"]["exercise"].is_string());
    let after = w.domains.head(domain).await.unwrap().0;
    assert!(after > before, "{after} > {before}");
    let (r, package) = send(
        &management,
        post("/console/api/proxy/adp/audit/export", signed),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&package)
    );
    assert_eq!(r.headers()[header::CONTENT_TYPE], "application/cbor-seq");
    assert_ne!(package, Vec::<u8>::new());
}

// OP-151 m.20 (d), m.19 (a), IA-5, OP-149 m.10, TN-128
#[tokio::test]
async fn the_consoles_section_probes_are_answered_by_the_real_decision_point() {
    let Console {
        management,
        browser,
        domain,
        root,
        w,
        ..
    } = console("mgmt-probes", true).await;
    let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
    let before = w.domains.head(domain).await.unwrap().0;
    let probe = |namespace: &str, name: &str, resource: &str| {
        let ask = serde_json::json!({
            "action": { "namespace": namespace, "name": name, "major": 1 },
            "resources": [{ "namespace": resource, "path": ["acme"] }],
            "mode": "check",
        })
        .to_string();
        let proof = browser.ais(
            domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::POST, "/console/api/intents"),
            Mode::Check,
            basis,
        );
        browser
            .request(&Method::POST, "/console/api/intents", "x")
            .header("x-access-ais", proof)
            .body(Body::from(ask))
            .unwrap()
    };
    let eligibility = |subject: &[u8], draft: &serde_json::Value| {
        let mut set = draft["probe"].clone();
        set["intent"] = draft["intent"].clone();
        let body = serde_json::json!({ "subject": b64url_encode(subject), "set": set });
        browser
            .request(
                &Method::POST,
                "/console/api/proxy/adp/eligibility:check",
                "x",
            )
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    for (namespace, name, resource) in [
        ("access", "authority_set_define", "access.domain"),
        ("access", "grant_amend", "access.domain"),
        ("access", "policy_set", "access.domain"),
        ("access", "anchor_amend", "access.domain"),
        ("access", "read", "access.audit"),
        ("idp.account", "suspend", "idp"),
    ] {
        let (r, body) = send(&management, probe(namespace, name, resource)).await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
        let draft: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(draft["probe"]["domain"], b64url_encode(&domain.0));
        let (r, body) = send(&management, eligibility(&root.0, &draft)).await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
        let answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(answer["eligible"], true, "{name}: {answer}");
        let (r, _) = send(&management, eligibility(&[0x5a; 16], &draft)).await;
        assert_eq!(
            r.status(),
            StatusCode::FORBIDDEN,
            "{name}: not the session's Party"
        );
    }
    assert_eq!(w.domains.head(domain).await.unwrap().0, before);
}

// OP-41, OP-44, U53, §17.6.8, X22, Ek B 3157, 3171, 3209
#[tokio::test]
async fn the_audit_stream_is_served_in_three_renderings_and_each_read_is_audited() {
    let Console {
        management,
        browser,
        domain,
        w,
        ..
    } = console("mgmt-audit", false).await;
    let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
    let read = |target: &str| {
        let proof = browser.ais(
            domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::GET, target),
            Mode::Check,
            basis,
        );
        browser
            .request(
                &Method::GET,
                &target.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                "",
            )
            .header("x-access-ais", proof)
            .body(Body::empty())
            .unwrap()
    };
    let audit_reads = || async {
        access_store::operational::operational_rows(&w.db.checkpointer, 10_000)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.event_type == "audit.read")
            .collect::<Vec<_>>()
    };
    let before = audit_reads().await.len();
    let (r, body) = send(&management, read("/admin/v1/realms/acme/audit/events")).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let ocsf: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let events = ocsf["items"].as_array().unwrap();
    assert!(
        !events.is_empty(),
        "the bootstrap and sign-in wrote audit rows"
    );
    assert!(events.iter().all(|e| e["class_uid"].is_u64()), "{ocsf}");
    let (r, body) = send(
        &management,
        read("/admin/v1/realms/acme/audit/events?format=cef"),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let cef: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        cef["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l.as_str().is_some_and(|l| l.starts_with("CEF:0|"))),
        "{cef}"
    );
    let (r, body) = send(
        &management,
        read("/admin/v1/realms/acme/audit/events?format=set"),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let set: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        set["items"][0]["iss"]
            .as_str()
            .unwrap()
            .starts_with("urn:suiss:access:realm:"),
        "{set}"
    );
    let (r, body) = send(
        &management,
        read("/admin/v1/realms/acme/audit/events?format=leef"),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let p: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(p["code"], "invalid-audit-format");
    let reads = audit_reads().await;
    assert_eq!(reads.len(), before + 3, "one audit.read per answered query");
    assert!(reads.iter().all(|r| r.domain == Some(domain.0)));
}
