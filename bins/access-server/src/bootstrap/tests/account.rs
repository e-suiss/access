//! The account pages end to end against the real decision point (OP-153 m.3 (w), (gg), m.8
//! (e)): a bootstrapped realm whose root signs in at the hosted login with a second factor;
//! the account BFF reuses that session, registers the browser's key as the session's device
//! Instance, forwards the hub's reads only with that key's statements and the revoke only as
//! the commit it signed, through ADP and the sequencer.

use std::net::{IpAddr, Ipv4Addr};

use access_experience::contract::Kind;
use access_experience::domain::plan;
use access_http::Limits;
use access_http::account::domain::{ACCOUNT_PEP, CSRF_COOKIE, read_intent};
use access_http::adp::adapters::{Discovery, router as adp_router};
use access_http::adp::app::Service;
use access_http::login::Peer;
use access_identity_account::app::claims::Issued;
use access_identity_account::domain::claims::ClaimOrder;
use access_identity_oauth::adapters::PgDirectory;
use access_identity_session::domain::assurance::{Factor, vector};
use access_identity_session::domain::session::cookie_digest;
use access_identity_ui::app::{Devices, Hosted};
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_identity_ui::ports::ApprovalClaims;
use access_internal_api::instances::cose_key;
use access_kernel::combinator::Mode;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, meta_anchor};
use access_kernel::model::Id;
use access_store::identity::{RealmId, TenantId};
use access_store::sessions::NewSession;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use suiss_crypto::signer::SoftSigner;

use super::management::{Browser, console_with, envelope_digest, now, send};
use super::*;

const HOST: &str = "access.test";
const ORIGIN: &str = "https://access.test";
const SESSION: &str = "__Host-access-session";
const BASE: &str = "/realms/acme/account/api";

/// The account pages issue no approval Claims.
struct NoClaims;

impl ApprovalClaims for NoClaims {
    fn issue(
        &self,
        _: TenantId,
        _: RealmId,
        _: &ClaimOrder,
    ) -> impl std::future::Future<Output = Result<Issued, access_internal_api::idp::Unavailable>> + Send
    {
        std::future::ready(Err(access_internal_api::idp::Unavailable(String::from(
            "none",
        ))))
    }
}

/// The realm's account pages over the token's realm keys and ADP in this process, as `main`
/// mounts them.
fn account_router(c: &super::management::Console) -> axum::Router {
    use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::app::local::LocalLimiter;
    use access_identity_account::app::login::LoginGate;
    use access_identity_account::domain::password::Argon2Params;
    use access_identity_account::domain::throttle::ThrottlePolicy;
    use access_identity_session::domain::session::SessionPolicy;
    use access_identity_ui::adapters::Outbox;
    let w = &c.w;
    let hosted = Arc::new(Hosted {
        kits: crate::login::HsmKits::new(
            crate::login::RealmKeks::new(Arc::clone(&w.keys)),
            w.db.router.clone(),
            w.db.app.clone(),
            SessionPolicy::DEFAULT,
        ),
        db: w.db.app.clone(),
        products: w.db.reader.clone(),
        clock: SystemClock,
        messages: Outbox,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(HasherConfig::sized(
            Argon2Params::CANONICAL,
            cores(),
            cgroup_memory_budget(),
        )),
        redirect_to: String::from("/"),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
    });
    let adp = adp_router(
        Service::new(w.domains.clone(), 64 * 1024),
        Discovery {
            issuer: String::from("https://access.test"),
        },
    );
    access_http::account::router(
        PgDirectory::new(w.db.router.clone()),
        hosted,
        Devices {
            signer: SignerKeys::new(w.identity_signer.clone()),
            instances: w.plane.clone(),
            approvals: w.plane.clone(),
            claims: NoClaims,
            pep: String::from(IDENTITY_PEP),
        },
        adp,
        None,
        Limits::default(),
    )
    .layer(axum::Extension(Peer(IpAddr::V4(Ipv4Addr::new(
        10, 9, 8, 7,
    )))))
}

/// A hosted login session of `subject`, authenticated just now with a password and a TOTP code
/// (AAL2), as the hosted login opens one.
async fn signed_in(c: &super::management::Console) -> String {
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    t.insert_session(&NewSession {
        cookie_hash: &cookie_digest(&value),
        subject: c.subject,
        session_epoch: 0,
        keep_signed_in: false,
        created_ms: i64::try_from(at).unwrap(),
        auth_time_ms: i64::try_from(at).unwrap(),
        idle_ms: 3_600_000,
        expires_ms: i64::try_from(at + 3_600_000).unwrap(),
        assurance: &serde_json::to_vec(&vector(&[Factor::password(at), Factor::totp([4; 16], at)]))
            .unwrap(),
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    b64url_encode(&value)
}

/// What the browser presents: the session cookie and, once read, the CSRF cookie.
struct Page {
    session: String,
    csrf: Option<String>,
}

impl Page {
    fn request(&self, method: &Method, path: &str) -> axum::http::request::Builder {
        let cookie = match &self.csrf {
            Some(t) => format!("{SESSION}={}; {CSRF_COOKIE}={t}", self.session),
            None => format!("{SESSION}={}", self.session),
        };
        let mut b = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::COOKIE, cookie)
            .header("sec-fetch-site", "same-origin");
        if *method != Method::GET {
            b = b
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(t) = &self.csrf {
                b = b.header("x-csrf-token", t);
            }
        }
        b
    }

    fn post(&self, path: &str, body: &Value) -> Request<Body> {
        self.request(&Method::POST, path)
            .body(Body::from(body.to_string()))
            .unwrap()
    }
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

fn csrf_of(r: &axum::http::Response<Body>) -> String {
    r.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix(&format!("{CSRF_COOKIE}=")))
        .and_then(|v| v.split(';').next())
        .unwrap()
        .to_owned()
}

/// A hub read of `kind` for the root, signed by `key` for `pep`.
fn hub_read(
    key: &Browser,
    pep: &str,
    domain: Digest,
    kind: Kind,
    viewer: Id,
    query: Option<Value>,
) -> Value {
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let read = plan::read(domain, kind, viewer, nonce, now()).unwrap();
    let digest = Digest(<[u8; 32]>::try_from(b64url_decode(&read.intent_digest).unwrap()).unwrap());
    let ais = key.ais_for(
        pep,
        domain,
        &nonce,
        digest,
        Mode::Check,
        ExerciseBasis::Anchor(meta_anchor(&domain)),
    );
    let mut body = read.body;
    body["context"]["ais"] = json!(ais);
    if let Some(q) = query {
        body["context"]["query"] = q;
    }
    body
}

fn browser(key: SoftSigner) -> Browser {
    Browser {
        jar: Vec::new(),
        csrf: String::new(),
        key,
    }
}

// OP-153 m.3 (w), m.8 (e), TN-128, TN-131, TN-110, MD-14, OP-149 m.6, OP-151 m.3 (e), X11,
// XI-3, XI-9, XI-22, HL-5, TI-8, INV-23, G57
#[tokio::test]
async fn the_account_pages_read_and_revoke_only_with_the_browsers_key() {
    let c = console_with("acct-bff", false, &sample_plan()).await;
    let app = account_router(&c);
    let domain = c.domain;
    let mut page = Page {
        session: signed_in(&c).await,
        csrf: None,
    };

    // G57
    let (r, _) = send(
        &app,
        Page {
            session: b64url_encode(&[0u8; 32]),
            csrf: None,
        }
        .request(&Method::GET, &format!("{BASE}/session"))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // §17.9.6
    let (r, _) = send(
        &app,
        page.request(&Method::GET, "/realms/nope/account/api/session")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    let (r, body) = send(
        &app,
        page.request(&Method::GET, &format!("{BASE}/session"))
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
    // OP-153 m.3 (t)
    let csp = r.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("'wasm-unsafe-eval'"));
    let s = json_of(&body);
    assert_eq!(s["realm"], "acme");
    assert_eq!(s["pep"], ACCOUNT_PEP);
    assert_eq!(s["party"], b64url_encode(&c.root.0));
    assert!(s["instance"].is_null());
    assert_eq!(s["api"], BASE);
    let csrf = csrf_of(&r);

    // TN-131
    let key = SoftSigner::generate_p256().unwrap().0;
    let cose = b64url_encode(&cose_key(&key.public_key()));
    let ask = json!({ "key": cose });
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/instances/challenge"), &ask),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(&body)["code"], "csrf-token-invalid");
    page.csrf = Some(csrf);
    let (r, body) = send(
        &app,
        page.request(&Method::POST, &format!("{BASE}/instances/challenge"))
            .header(header::ORIGIN, "https://evil.test")
            .body(Body::from(ask.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(&body)["code"], "origin-not-allowed");

    // TN-128
    let me = browser(key);
    let read = hub_read(&me, ACCOUNT_PEP, domain, Kind::Inventory, c.root, None);
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/inventory"), &read),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(&body)["code"], "account-instance-required");

    // OP-149 m.6, X11
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/instances/challenge"), &ask),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let ch = json_of(&body);
    assert_eq!(ch["party"], b64url_encode(&c.root.0));
    assert!(ch.get("register").is_none());
    let grant =
        <[u8; 16]>::try_from(b64url_decode(ch["basis"].as_str().unwrap()).unwrap()).unwrap();
    let challenge = b64url_decode(ch["challenge"].as_str().unwrap()).unwrap();
    let create = me.ais_for(
        ch["pep"].as_str().unwrap(),
        domain,
        &challenge,
        envelope_digest(ch["create"].as_str().unwrap()),
        Mode::Commit,
        ExerciseBasis::Public(Id(grant)),
    );
    let registration = json!({
        "challenge": ch["challenge"],
        "party": ch["party"],
        "key": cose,
        "valid_from": ch["valid_from"],
        "valid_until": ch["valid_until"],
        "ais": create,
    });
    let (r, body) = send(&app, page.post(&format!("{BASE}/instances"), &registration)).await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (_, body) = send(
        &app,
        page.request(&Method::GET, &format!("{BASE}/session"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let s = json_of(&body);
    assert_eq!(
        s["instance"],
        b64url_encode(&access_kernel::verify::key_scope::thumbprint(
            &me.key.public_key()
        ))
    );
    // INV-13
    let (r, _) = send(
        &app,
        page.post(&format!("{BASE}/instances/challenge"), &ask),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // TN-128
    let mut bare = read.clone();
    bare["context"].as_object_mut().unwrap().remove("ais");
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/inventory"), &bare),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(&body)["code"], "read-not-own");
    let stranger = browser(SoftSigner::generate_p256().unwrap().0);
    let foreign = hub_read(
        &stranger,
        ACCOUNT_PEP,
        domain,
        Kind::Inventory,
        c.root,
        None,
    );
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/inventory"), &foreign),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(&body)["code"], "read-not-own");
    let elsewhere = hub_read(
        &me,
        ACCOUNT_PEP,
        Digest([0x42; 32]),
        Kind::Inventory,
        c.root,
        None,
    );
    let (r, _) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/inventory"), &elsewhere),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // OP-153 m.8 (a)
    for rest in ["search/subject", "eligibility:check", "audit/export"] {
        let (r, _) = send(&app, page.post(&format!("{BASE}/proxy/adp/{rest}"), &read)).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{rest}");
    }

    // OP-153 m.8 (a), XI-9
    let head = c.w.domains.head(domain).await.unwrap().0;
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/inventory"), &read),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let inventory = json_of(&body);
    let given = inventory["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| {
            v["type"] == "holding"
                && v["holder"].get("party").is_some()
                && v["groups"]
                    .as_array()
                    .is_some_and(|g| g.iter().any(|x| x == "shared_from_you"))
        })
        .unwrap()
        .clone();
    let grant_text = given["grant"].as_str().unwrap().to_owned();
    // XI-22
    let theirs = hub_read(
        &me,
        ACCOUNT_PEP,
        domain,
        Kind::Inventory,
        Id([0x5a; 16]),
        None,
    );
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/inventory"), &theirs),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(json_of(&body)["results"], json!([]));
    let activity = hub_read(&me, ACCOUNT_PEP, domain, Kind::Activity, c.root, None);
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/activity"), &activity),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let uses_before = json_of(&body)["results"].as_array().unwrap().len();
    assert_eq!(c.w.domains.head(domain).await.unwrap().0, head);

    // PI-7
    let payload = json!({ "grant_revoke": { "grant": grant_text } });
    let ask = json!({ "action": { "namespace": "access", "name": "grant_revoke", "major": 1 }, "payload": payload, "mode": "commit" });
    let (r, _) = send(&app, page.post(&format!("{BASE}/intents"), &ask)).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let proof = |who: &Browser| {
        who.ais_for(
            ACCOUNT_PEP,
            domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::POST, &format!("{BASE}/intents")),
            Mode::Check,
            ExerciseBasis::Anchor(meta_anchor(&domain)),
        )
    };
    let (r, body) = send(
        &app,
        page.request(&Method::POST, &format!("{BASE}/intents"))
            .header("x-access-ais", proof(&stranger))
            .body(Body::from(ask.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_of(&body)["code"], "read-proof-rejected");
    let (r, body) = send(
        &app,
        page.request(&Method::POST, &format!("{BASE}/intents"))
            .header("x-access-ais", proof(&me))
            .body(Body::from(ask.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let drafted = json_of(&body);
    let anchor = Id(<[u8; 16]>::try_from(
        b64url_decode(drafted["basis"]["anchor"].as_str().unwrap()).unwrap(),
    )
    .unwrap());

    // TN-110, MD-14
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let commit = |who: &Browser, mode: Mode| {
        let ais = who.ais_for(
            ACCOUNT_PEP,
            domain,
            &nonce,
            envelope_digest(drafted["envelope"].as_str().unwrap()),
            mode,
            ExerciseBasis::Anchor(anchor),
        );
        let resource = &drafted["intent"]["resources"][0];
        json!({
            "subject": { "type": "access_party", "id": b64url_encode(&c.root.0) },
            "action": { "name": "grant_revoke" },
            "resource": { "type": resource["namespace"], "id": resource["path"][0] },
            "context": {
                "domain": b64url_encode(&domain.0),
                "mode": "commit",
                "nonce": b64url_encode(&nonce),
                "intent": drafted["intent"],
                "payload": drafted["payload"],
                "basis": { "anchor": b64url_encode(&anchor.0) },
                "capacity": "own",
                "ais": ais,
            },
        })
    };
    for (who, mode) in [(&stranger, Mode::Commit), (&me, Mode::Check)] {
        let (r, body) = send(
            &app,
            page.post(&format!("{BASE}/proxy/adp/evaluation"), &commit(who, mode)),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_of(&body)["code"], "commit-ais-rejected");
    }
    assert_eq!(c.w.domains.head(domain).await.unwrap().0, head);
    let signed = commit(&me, Mode::Commit);
    let (r, first) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/evaluation"), &signed),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&first)
    );
    let first = json_of(&first);
    assert_eq!(first["decision"], true, "{first}");
    let recorded = c.w.domains.head(domain).await.unwrap().0;
    assert!(recorded > head);
    // HL-5, TI-8
    let (r, again) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/evaluation"), &signed),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let again = json_of(&again);
    assert_eq!(first["context"]["exercise"], again["context"]["exercise"]);
    assert_eq!(again["context"]["replayed"], true);
    assert_eq!(c.w.domains.head(domain).await.unwrap().0, recorded);

    // XI-3, INV-23
    let read = hub_read(&me, ACCOUNT_PEP, domain, Kind::Inventory, c.root, None);
    let (_, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/inventory"), &read),
    )
    .await;
    assert!(
        json_of(&body)["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["grant"] != json!(grant_text))
    );
    let activity = hub_read(&me, ACCOUNT_PEP, domain, Kind::Activity, c.root, None);
    let (_, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/activity"), &activity),
    )
    .await;
    assert!(json_of(&body)["results"].as_array().unwrap().len() >= uses_before);
    let changes = hub_read(&me, ACCOUNT_PEP, domain, Kind::Changes, c.root, None);
    let (r, body) = send(
        &app,
        page.post(&format!("{BASE}/proxy/adp/search/changes"), &changes),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        json_of(&body)["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == "grant" && v["ended"] == true),
        "the revoke shows in Changes as information"
    );
    c.w.domains.release().await;
}
