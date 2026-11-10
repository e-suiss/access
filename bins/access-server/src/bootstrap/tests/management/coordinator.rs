//! Needs Attention on the real server path (§8.17.6.5, IA-1, X5, X6, OP-156 m.3 (t)): the realm
//! names its coordinator with `idp.realm.coordinator` through the admin API; Access publishes it
//! in the realm's Suiss discovery document; the experience service asks that coordinator's public
//! endpoint for the reader's count and shows one link. Access keeps no queue.

use std::sync::atomic::{AtomicU64, Ordering};

use access_experience::adapters::{Beacon, router as experience_router};
use access_experience::app::Experience;
use access_experience::contract::{Hub, Kind, Plan};
use access_experience::ports::{Clock, Random, Upstream};
use access_http::adp::adapters::{Discovery as AdpDiscovery, Pep, router as adp_router};
use access_http::adp::app::Service;
use access_identity_oauth::app::Discovery as RealmDiscovery;
use access_identity_oauth::domain::suiss::Settings as SuissSettings;
use access_kernel::meta::meta_anchor;
use access_sdk::transport::{Answer, Fault, Response as Answered};
use serde_json::{Value, json};

use super::*;

const EXPERIENCE_PEP: &str = "access-experience-test";

/// The coordinator's public Needs Attention endpoint.
const ATTENTION: &str = "https://work.test/attention";

/// A coordinator twin's public endpoint: it counts what waits for each Party; Access never does.
#[derive(Default)]
struct CoordinatorTwin {
    waiting: AtomicU64,
    asked: AtomicU64,
}

impl CoordinatorTwin {
    fn answer(&self, party: &str) -> Value {
        self.asked.fetch_add(1, Ordering::SeqCst);
        json!({
            "count": self.waiting.load(Ordering::SeqCst),
            "href": format!("https://work.test/inbox?for={party}"),
        })
    }
}

/// Access's public routes and the coordinator twin, reached in process.
#[derive(Clone)]
struct Public {
    adp: axum::Router,
    discovery: axum::Router,
    domain: String,
    coordinator: Arc<CoordinatorTwin>,
}

async fn answer(router: &axum::Router, req: Request<Body>) -> Answer {
    let r = router.clone().oneshot(req).await.unwrap();
    let status = r.status().as_u16();
    let body = to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec();
    Answer::Response(Answered::new(status, body))
}

impl Upstream for Public {
    async fn search(&self, domain: &str, kind: Kind, body: Vec<u8>) -> Answer {
        if domain != self.domain {
            return Answer::Unanswered(Fault::Unreachable);
        }
        let mut req = Request::post(format!("/access/v1/search/{}", kind.search()))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(Pep(EXPERIENCE_PEP.to_owned()));
        answer(&self.adp, req).await
    }

    async fn discovery(&self, realm: &str) -> Answer {
        let req = Request::get(format!("/.well-known/suiss-configuration/realms/{realm}"))
            .header(header::HOST, "access.test")
            .body(Body::empty())
            .unwrap();
        answer(&self.discovery, req).await
    }

    async fn attention(&self, url: &str, party: &str) -> Answer {
        if url != ATTENTION {
            return Answer::Unanswered(Fault::Unreachable);
        }
        Answer::Response(Answered::new(
            200,
            self.coordinator.answer(party).to_string().into_bytes(),
        ))
    }
}

struct Wall;

impl Clock for Wall {
    fn now(&self) -> u64 {
        now_ms()
    }
}

impl Random for Wall {
    fn nonce(&self) -> Option<[u8; 16]> {
        access_crypto::random::bytes().ok()
    }
}

async fn call(app: &axum::Router, path: &str, body: &Value) -> Value {
    let (r, bytes) = send(
        app,
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

/// The root's hub over the realm `acme`, read with its browser's signed reads.
async fn hub(c: &Console, app: &axum::Router) -> Hub {
    let viewer = b64url_encode(&c.root.0);
    let domain = b64url_encode(&c.domain.0);
    let plan: Plan = serde_json::from_value(
        call(
            app,
            "/experience/v1/hub/plan",
            &json!({ "viewer": viewer, "domains": [{ "domain": domain }], "kinds": ["inventory"] }),
        )
        .await,
    )
    .unwrap();
    let reads: Vec<Value> = plan
        .reads
        .iter()
        .map(|r| {
            let digest =
                Digest(<[u8; 32]>::try_from(b64url_decode(&r.intent_digest).unwrap()).unwrap());
            let nonce = b64url_decode(&r.nonce).unwrap();
            let ais = c.browser.ais_for(
                &plan.pep,
                c.domain,
                &nonce,
                digest,
                Mode::Check,
                ExerciseBasis::Anchor(meta_anchor(&c.domain)),
            );
            let mut body = r.body.clone();
            body["context"]["ais"] = json!(ais);
            json!({ "domain": r.domain, "kind": r.kind, "body": body })
        })
        .collect();
    serde_json::from_value(
        call(
            app,
            "/experience/v1/hub",
            &json!({ "viewer": viewer, "reads": reads, "realm": "acme" }),
        )
        .await,
    )
    .unwrap()
}

// §8.17.6.5, IA-1, X5, X6, OP-156 m.3 (t), Ek B 5256
#[tokio::test]
async fn the_hub_links_to_the_coordinator_the_realm_names_with_its_count() {
    let c = console("q16-attention", true).await;
    let coordinator = Arc::new(CoordinatorTwin::default());
    coordinator.waiting.store(3, Ordering::SeqCst);
    let discovery = access_http::realm::router(
        RealmDiscovery::new(
            PgDirectory::new(c.w.db.router.clone()).with_facts(c.w.db.app.clone()),
            SignerKeys::new(c.w.identity_signer.clone()),
        )
        .with_suiss(SuissSettings {
            region: String::from("eu-test"),
            relay: String::from("https://relay.test"),
            management_api: String::from("https://access.test/admin/v1"),
            api_base: String::from("https://access.test"),
            products: std::collections::BTreeMap::new(),
        }),
    );
    let public = Public {
        adp: adp_router(
            Service::new(c.w.domains.clone(), 64 * 1024),
            AdpDiscovery {
                issuer: String::from("https://access.test"),
            },
        ),
        discovery,
        domain: b64url_encode(&c.domain.0),
        coordinator: coordinator.clone(),
    };
    let app = experience_router(
        Experience::new(public.clone(), Wall, Wall, String::from(EXPERIENCE_PEP)),
        Beacon::default(),
    );

    // IA-1
    let before = hub(&c, &app).await;
    assert_eq!(before.attention, None);
    assert_eq!(coordinator.asked.load(Ordering::SeqCst), 0);

    // OP-156 m.3 (t)
    let refused = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/coordinator",
            ("putCoordinator", None),
            json!({ "attention_url": "http://work.test/attention" }),
            None,
        )
        .await;
    assert!(
        !refused.status.is_success(),
        "{} {}",
        refused.status,
        refused.body
    );
    let named = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/coordinator",
            ("putCoordinator", None),
            json!({ "attention_url": ATTENTION }),
            None,
        )
        .await;
    assert!(named.status.is_success(), "{} {}", named.status, named.body);

    // X6
    let after = hub(&c, &app).await;
    let attention = after.attention.unwrap();
    assert_eq!(attention.count, 3);
    assert_eq!(
        attention.href,
        format!("https://work.test/inbox?for={}", b64url_encode(&c.root.0))
    );
    assert_eq!(attention.text, "attention.approvals_waiting");
    assert_eq!(coordinator.asked.load(Ordering::SeqCst), 1);

    // IA-1
    coordinator.waiting.store(0, Ordering::SeqCst);
    assert_eq!(hub(&c, &app).await.attention, None);
    let cleared = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/coordinator",
            ("putCoordinator", None),
            json!({ "attention_url": null }),
            None,
        )
        .await;
    assert!(
        cleared.status.is_success(),
        "{} {}",
        cleared.status,
        cleared.body
    );
    coordinator.waiting.store(5, Ordering::SeqCst);
    assert_eq!(hub(&c, &app).await.attention, None);
    assert_eq!(coordinator.asked.load(Ordering::SeqCst), 2);
}
