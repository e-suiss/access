//! The management surface end to end against the real sequencer (OP-151 m.2 M1b, m.12, Ek B
//! 3300): a bootstrapped realm with its console client, a user signed in at the realm's own
//! authorization server, the console's session and device Instance, a read through the BFF with
//! a read proof and a realm-issued, DPoP-bound read token, and a branding write that the BFF
//! passes on with the browser's AIS and that moves the domain's log.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use access_authority_core::genesis::IDP_ANCHOR;
use access_http::console::domain::read_intent;
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
        let s = Statement {
            domain,
            nonce: nonce.to_vec(),
            intent,
            mode,
            pep: String::from(access_identity_ui::domain::frontend::IDENTITY_PEP),
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

// OP-151 m.12 (b), (c), (e), TN-128, TN-129, TN-130, TN-110, TN-27, Ek B 3300: the console
// signs in at the realm's own authorization server with its client key, opens its session,
// registers the browser's Instance, reads the settings through the BFF with a read proof and a
// DPoP-bound realm read token, and writes branding with the browser's AIS: the Exercise is
// committed by the real sequencer and the domain's log moves
#[tokio::test]
async fn the_console_signs_in_reads_and_writes_through_the_sequencer() {
    let w = World::new("mgmt-e2e").await;
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
    crate::jobs::open_now(&w.db.app, &w.db.archive, "mgmt-e2e").await;
    let day = u32::try_from(now() / 86_400_000).unwrap();
    for d in [day - 1, day, day + 1] {
        access_store::dpop::open_dpop_replay_day(&w.db.archive, d)
            .await
            .unwrap();
    }

    // the realm's founder signs in: a subject bound to the founding root's Party
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
        },
        crate::admin::InProcessRoutes {
            oauth: oauth.clone(),
            adp: axum::Router::new(),
        },
        None,
    )
    .unwrap()
    .layer(axum::Extension(Peer(IpAddr::V4(Ipv4Addr::new(
        10, 1, 2, 3,
    )))));

    // TN-131, OP-151 m.12 (b): the console sends the browser to the realm's /authorize
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

    // TN-128, TN-129: the callback exchanges the code with the client key and opens the session
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
    let mut browser = Browser {
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

    // OP-149 m.6, OP-151 m.3 (e): the browser's key opens the session's device Instance
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

    // TN-128, TN-130: a read proof gets a realm-issued, DPoP-bound read token at the BFF
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

    // the cookie alone reads nothing (OP-151 m.3 (s))
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

    // TN-110, OP-151 m.11 (a): the draft is a read; the write carries the browser's AIS
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

    // TN-130, TN-27, OP-21: the verifier takes a realm read token only with a fresh proof by
    // its bound key; a bearer presentation, another key, a replayed proof, another surface or a
    // token whose console session ended reads nothing
    use access_http::api::domain::SurfaceScope;
    use access_http::api::domain::caller::{MAX_TOKEN_LIFETIME_MS, Refusal, check_read};
    use access_http::api::ports::{Presented, ReadTokens as _};
    use access_http::console::ports::DpopKeys as _;
    let tokens = crate::admin::tokens::ManagementTokens {
        directory: PgDirectory::new(w.db.router.clone()),
        signer: SignerKeys::new(w.identity_signer.clone()),
        app: w.db.app.clone(),
        plane: w.plane.clone(),
        dpop: DpopProfile::default(),
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
