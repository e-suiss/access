//! The experience backend against the real decision point (CMP-16, OP-153 m.3 (v), (gg)): a
//! bootstrapped realm whose root signed in to the console and registered the browser's key as a
//! device Instance; the experience service reads the hub with the browser's signed reads through
//! ADP's public search route, as its own transport-authenticated PEP; a revoke goes from the
//! browser to ADP directly and the hub shows its outcome only once recorded.

use std::collections::BTreeMap;

use access_experience::adapters::{Beacon, router as experience_router};
use access_experience::app::Experience;
use access_experience::contract::{Freshness, Hub, Kind, Owner, Plan};
use access_experience::domain::honesty::{self, Answer as Seen, Attempt, Next, Path, Sent, Shown};
use access_experience::ports::{Clock, Random, Upstream};
use access_http::adp::adapters::{Discovery, Pep, router as adp_router};
use access_http::adp::app::Service;
use access_http::console::drafts::wire;
use access_kernel::combinator::Mode;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, Payload, core_action, meta_anchor};
use access_kernel::model::{ResourceRef, Window};
use access_sdk::transport::{Answer, Fault, Response as Answered};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::management::{Console, console_with, send};
use super::*;

/// The experience service's PEP name, as the TLS layer would set it from its certificate.
const EXPERIENCE_PEP: &str = "access-experience-test";

/// The PEP the browser's write goes through.
const ACCOUNT_PEP: &str = "access-account-test";

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// ADP in this process, reached as the transport-authenticated `pep`; any other domain is
/// unreachable.
#[derive(Clone)]
struct InProcess {
    adp: axum::Router,
    domain: String,
}

impl InProcess {
    async fn post(&self, pep: &str, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
        let mut req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(Pep(pep.to_owned()));
        let r = self.adp.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        (
            status,
            to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec(),
        )
    }
}

impl Upstream for InProcess {
    async fn search(&self, domain: &str, kind: Kind, body: Vec<u8>) -> Answer {
        if domain != self.domain {
            return Answer::Unanswered(Fault::Unreachable);
        }
        let (status, body) = self
            .post(
                EXPERIENCE_PEP,
                &format!("/access/v1/search/{}", kind.search()),
                body,
            )
            .await;
        Answer::Response(Answered::new(status, body))
    }
}

struct SystemTime;

impl Clock for SystemTime {
    fn now(&self) -> u64 {
        now_ms()
    }
}

impl Random for SystemTime {
    fn nonce(&self) -> Option<[u8; 16]> {
        access_crypto::random::bytes().ok()
    }
}

async fn call(app: &axum::Router, path: &str, body: &Value) -> (StatusCode, Value) {
    let (r, bytes) = send(
        app,
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    (
        r.status(),
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The browser signs every planned read of `plan` for `domain` with its device key.
fn signed(c: &Console, plan: &Plan, labels: &BTreeMap<String, String>) -> Vec<Value> {
    plan.reads
        .iter()
        .map(|r| {
            let digest = Digest(
                <[u8; 32]>::try_from(b64url_decode(&r.intent_digest).unwrap()).unwrap(),
            );
            let nonce = b64url_decode(&r.nonce).unwrap();
            let d = Digest(<[u8; 32]>::try_from(b64url_decode(&r.domain).unwrap()).unwrap());
            let ais = c.browser.ais_for(
                &plan.pep,
                d,
                &nonce,
                digest,
                Mode::Check,
                ExerciseBasis::Anchor(meta_anchor(&d)),
            );
            let mut body = r.body.clone();
            body["context"]["ais"] = json!(ais);
            json!({ "domain": r.domain, "label": labels.get(&r.domain), "kind": r.kind, "body": body })
        })
        .collect()
}

async fn hub(c: &Console, app: &axum::Router, domains: &[(&str, &str)], depth: &str) -> Hub {
    let viewer = b64url_encode(&c.root.0);
    let (status, plan) = call(
        app,
        "/experience/v1/hub/plan",
        &json!({
            "viewer": viewer,
            "domains": domains.iter().map(|(d, l)| json!({ "domain": d, "label": l })).collect::<Vec<_>>(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{plan}");
    let plan: Plan = serde_json::from_value(plan).unwrap();
    assert_eq!(plan.pep, EXPERIENCE_PEP);
    let labels = domains
        .iter()
        .map(|(d, l)| ((*d).to_owned(), (*l).to_owned()))
        .collect();
    let reads = signed(c, &plan, &labels);
    let (status, hub) = call(
        app,
        "/experience/v1/hub",
        &json!({ "viewer": viewer, "depth": depth, "reads": reads }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{hub}");
    serde_json::from_value(hub).unwrap()
}

/// The browser's `grant_revoke` of `grant` as an ADP commit body, signed for `ACCOUNT_PEP`.
fn revoke_body(c: &Console, grant: access_kernel::model::Id, nonce: &[u8], now: u64) -> Vec<u8> {
    let payload = Payload::GrantRevoke { grant };
    let intent = IntentEnvelope {
        provenance: BTreeMap::new(),
        action: core_action("grant_revoke"),
        resources: vec![ResourceRef {
            namespace: String::from("access.party"),
            path: vec![String::from("p")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::from([(String::from("payload"), payload.digest().unwrap())]),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: now.saturating_sub(60_000),
            until: now + 600_000,
        },
    };
    let digest = intent_digest(&intent).unwrap();
    let basis = ExerciseBasis::Anchor(meta_anchor(&c.domain));
    let ais = c
        .browser
        .ais_for(ACCOUNT_PEP, c.domain, nonce, digest, Mode::Commit, basis);
    let mut wired = wire(&intent);
    wired["opaque"] = json!({ "payload": b64url_encode(&payload.digest().unwrap().0) });
    json!({
        "subject": { "type": "access_party", "id": b64url_encode(&c.root.0) },
        "action": { "name": "grant_revoke" },
        "resource": { "type": "access.party", "id": "p" },
        "context": {
            "domain": b64url_encode(&c.domain.0),
            "mode": "commit",
            "nonce": b64url_encode(nonce),
            "intent": wired,
            "payload": b64url_encode(&payload.to_bytes().unwrap()),
            "basis": { "anchor": b64url_encode(&meta_anchor(&c.domain).0) },
            "capacity": "own",
            "ais": ais,
        },
    })
    .to_string()
    .into_bytes()
}

// CMP-16, XI-18, IA-7, X6, XI-10, XI-11, XI-5, XI-16, XI-9, XI-22, IA-2, SI-21, XI-1, §8.17.7.2,
// OP-153 m.3 (v), (gg), Ek B 3731, 3745, 3751, 3839, 3987
#[tokio::test]
async fn the_hub_is_read_with_the_browsers_ais_through_the_public_search() {
    let c = console_with("exp-hub", false, &sample_plan()).await;
    let acme = b64url_encode(&c.domain.0);
    let elsewhere = b64url_encode(&[0x42; 32]);
    let adp = adp_router(
        Service::new(c.w.domains.clone(), 64 * 1024),
        Discovery {
            issuer: String::from("https://access.test"),
        },
    );
    let upstream = InProcess {
        adp: adp.clone(),
        domain: acme.clone(),
    };
    let app = experience_router(
        Experience::new(
            upstream.clone(),
            SystemTime,
            SystemTime,
            String::from(EXPERIENCE_PEP),
        ),
        Beacon::default(),
    );
    let head = c.w.domains.head(c.domain).await.unwrap().0;

    let seen = hub(
        &c,
        &app,
        &[(&acme, "Acme"), (&elsewhere, "Shop")],
        "default",
    )
    .await;
    // X6, XI-10, XI-11, XI-5
    let given = seen
        .shared_from_you
        .iter()
        .find(|r| r.who.kind == "party")
        .unwrap();
    assert!(
        seen.shared_from_you
            .iter()
            .any(|r| r.who.kind == "everyone"),
        "the Genesis bootstrap Grant the root gave everyone is shared from the root too"
    );
    assert_eq!(given.capacity[0].text, "capacity.own_use");
    assert_eq!(given.label.as_deref(), Some("Acme"));
    let revoke = given.offers.iter().find(|o| o.action == "revoke").unwrap();
    assert!(revoke.available && revoke.steps <= 2);
    assert!(
        seen.roots
            .iter()
            .any(|r| r.sole && r.confirm == "root.sole_confirm")
    );
    // XI-16, §8.17.7.2
    let shop = seen.domains.iter().find(|d| d.domain == elsewhere).unwrap();
    assert_eq!(shop.text, "domain.unreachable");
    assert!(shop.as_of.is_none());
    let mine = seen.domains.iter().find(|d| d.domain == acme).unwrap();
    assert!(mine.as_of.is_some());
    assert!(
        seen.notices
            .contains(&String::from("hub.not_shown_unconnected"))
    );
    // XI-1, E25
    assert_eq!(
        (shop.owner, shop.freshness),
        (Owner::Access, Freshness::Unknown)
    );
    let rows = seen
        .acting_for_you
        .iter()
        .chain(&seen.shared_from_you)
        .chain(&seen.your_authority);
    let owned: Vec<(Owner, &str)> = rows
        .map(|r| (r.owner, r.domain.as_str()))
        .chain(seen.roots.iter().map(|r| (r.owner, r.domain.as_str())))
        .chain(seen.activity.iter().map(|r| (r.owner, r.domain.as_str())))
        .chain(seen.changes.iter().map(|r| (r.owner, r.domain.as_str())))
        .collect();
    assert!(owned.len() > 3, "{owned:?}");
    assert!(
        owned
            .iter()
            .all(|(owner, domain)| *owner == Owner::Access && *domain == acme),
        "every row carries the one owner whose record it is, and the unreachable domain shows no row"
    );
    // IA-2, SI-21
    assert!(
        seen.changes
            .iter()
            .any(|ch| ch.kind == "instance" && ch.own),
        "{:?}",
        seen.changes
    );
    assert!(seen.changes.iter().all(|ch| ch.derived));
    assert_eq!(
        c.w.domains.head(c.domain).await.unwrap().0,
        head,
        "reading the hub writes nothing"
    );

    // XI-9, XI-22
    let stranger = b64url_encode(&[0x5a; 16]);
    let plan: Plan = serde_json::from_value(
        call(
            &app,
            "/experience/v1/hub/plan",
            &json!({ "viewer": stranger, "domains": [{ "domain": acme }], "kinds": ["inventory"] }),
        )
        .await
        .1,
    )
    .unwrap();
    let foreign = signed(&c, &plan, &BTreeMap::new());
    let (status, body) = upstream
        .post(
            EXPERIENCE_PEP,
            "/access/v1/search/inventory",
            serde_json::to_vec(&foreign[0]["body"]).unwrap(),
        )
        .await;
    assert_eq!(status, 200);
    let answer: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        answer["results"],
        json!([]),
        "another Party's inventory reads empty"
    );

    // OP-153 m.3 (v)
    drop(app);
    let plan_again = experience_router(
        Experience::new(
            upstream.clone(),
            SystemTime,
            SystemTime,
            String::from(EXPERIENCE_PEP),
        ),
        Beacon::default(),
    );
    let fresh: Plan = serde_json::from_value(
        call(
            &plan_again,
            "/experience/v1/hub/plan",
            &json!({ "viewer": b64url_encode(&c.root.0), "domains": [{ "domain": acme }], "kinds": ["inventory"] }),
        )
        .await
        .1,
    )
    .unwrap();
    drop(plan_again);
    let direct = signed(&c, &fresh, &BTreeMap::new());
    let (status, body) = upstream
        .post(
            EXPERIENCE_PEP,
            "/access/v1/search/inventory",
            serde_json::to_vec(&direct[0]["body"]).unwrap(),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        answer["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["type"] == "holding")
    );
    for (method, path) in [
        ("POST", "/access/v1/evaluation"),
        ("POST", "/experience/v1/commit"),
        ("PUT", "/experience/v1/hub"),
    ] {
        let app = experience_router(
            Experience::new(
                upstream.clone(),
                SystemTime,
                SystemTime,
                String::from(EXPERIENCE_PEP),
            ),
            Beacon::default(),
        );
        let (r, _) = send(
            &app,
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert!(
            r.status() == StatusCode::NOT_FOUND || r.status() == StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}: no write path"
        );
    }
    c.w.domains.release().await;
}

// XI-3, G39, HL-5, TI-8, X26, XI-5, INV-23, §8.13, Ek B 3695, 3922, 3923, 3926
#[tokio::test]
async fn a_revoke_is_shown_done_only_once_recorded_and_its_retry_is_idempotent() {
    let c = console_with("exp-revoke", false, &sample_plan()).await;
    let acme = b64url_encode(&c.domain.0);
    let adp = adp_router(
        Service::new(c.w.domains.clone(), 64 * 1024),
        Discovery {
            issuer: String::from("https://access.test"),
        },
    );
    let upstream = InProcess {
        adp,
        domain: acme.clone(),
    };
    let app = experience_router(
        Experience::new(
            upstream.clone(),
            SystemTime,
            SystemTime,
            String::from(EXPERIENCE_PEP),
        ),
        Beacon::default(),
    );
    let before = hub(&c, &app, &[(&acme, "Acme")], "expert").await;
    let sample = before
        .shared_from_you
        .iter()
        .find(|r| r.who.kind == "party")
        .unwrap();
    let grant_text = sample.grant.clone();
    let grant = access_kernel::model::Id(
        <[u8; 16]>::try_from(b64url_decode(&grant_text).unwrap()).unwrap(),
    );
    assert!(sample.expert.is_some());

    let now = server_time(&c.w.db.app).await.unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let body = revoke_body(&c, grant, &nonce, now);
    // XI-3
    let mut attempt = Attempt {
        sent: Sent::Sent,
        path: Path::Direct,
        answer: Seen::Nothing,
        timed_out: false,
        valid_until: now + 600_000,
    };
    assert_eq!(honesty::shown(&attempt), Shown::Submitted);
    let head = c.w.domains.head(c.domain).await.unwrap().0;
    let (status, first) = upstream
        .post(ACCOUNT_PEP, "/access/v1/evaluation", body.clone())
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&first));
    let recorded = c.w.domains.head(c.domain).await.unwrap().0;
    assert!(recorded > head);
    // G39, §8.13
    attempt.timed_out = true;
    assert_eq!(honesty::shown(&attempt), Shown::Checking);
    assert_eq!(honesty::next(&attempt, now), Next::RetrySameNonce);
    // HL-5, TI-8
    let (status, again) = upstream
        .post(ACCOUNT_PEP, "/access/v1/evaluation", body)
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&again));
    let (a, b): (Value, Value) = (
        serde_json::from_slice(&first).unwrap(),
        serde_json::from_slice(&again).unwrap(),
    );
    assert_eq!(a["decision"], true, "{a}");
    // §9.5, §9.11, Ek B 5893: no witness is declared here, so nothing is witnessed
    assert_eq!(a["context"]["witnessed_through"], "0", "{a}");
    assert_eq!(a["context"]["exercise"], b["context"]["exercise"]);
    assert_eq!(b["context"]["replayed"], true);
    assert_eq!(
        c.w.domains.head(c.domain).await.unwrap().0,
        recorded,
        "recorded once"
    );
    attempt.answer = honesty::answer_of(status, &again);
    assert_eq!(honesty::shown(&attempt), Shown::Confirmed);
    assert_eq!(honesty::next(&attempt, now), Next::Done);

    // XI-3, INV-23
    let after = hub(&c, &app, &[(&acme, "Acme")], "default").await;
    assert!(
        after.shared_from_you.iter().all(|r| r.grant != grant_text),
        "the revoked Grant leaves the inventory once recorded"
    );
    assert!(
        !after.activity.is_empty()
            && after
                .activity
                .iter()
                .all(|u| u.text == "activity.by_you" || u.text == "activity.for_you"),
        "past uses stay history"
    );
    assert!(after.activity.len() >= before.activity.len());
    c.w.domains.release().await;
}

mod surfaces;
