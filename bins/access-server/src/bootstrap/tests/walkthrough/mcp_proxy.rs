//! MCP proxy / credential broker (§11.19, §11.6, §11.13): the broker is a PEP, never an actor;
//! the agent acts through its own Instance on P's Grant for P; the broker asks the ADP with the
//! agent's statement in context and its own transport identity only as `pep`; P's upstream
//! account is connected only after P's consent for the agent's client (AS-M15); a token leaves
//! the vault only for that allowed Exercise; and once P's Grant is revoked there is no new
//! decision and the token set is shredded.

use access_http::adp::adapters::Pep as PepId;
use access_identity_vault::domain::resource::VaultChange;
use access_kernel::json::b64url_decode;
use access_sdk::agent::contract::{Adp, Exercise, Plan as AgentPlan, Step};
use access_sdk::transport::Answer;
use axum::http::{Method, StatusCode};

use super::super::vault::{EXECUTOR, Lab};
use super::*;

/// The broker in front of the ADP: it forwards the agent's request as its own PEP.
struct Broker {
    adp: axum::Router,
    paths: std::sync::Mutex<Vec<String>>,
}

impl Adp for Broker {
    fn evaluate(&self, body: &str) -> Answer {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request as HttpRequest, header};
        use tower::ServiceExt as _;
        let path = "/access/v1/evaluation";
        self.paths.lock().unwrap().push(String::from(path));
        let mut req = HttpRequest::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        req.extensions_mut().insert(PepId(String::from(EXECUTOR)));
        let r = super::super::agent::block(self.adp.clone().oneshot(req)).unwrap();
        let status = r.status().as_u16();
        let body = super::super::agent::block(to_bytes(r.into_body(), 1 << 22))
            .unwrap()
            .to_vec();
        Answer::Response(access_sdk::transport::Response::new(status, body))
    }
}

// §11.19, §11.6, §11.13, AS-M15, MD-13, EI-26, G59, AGI-2, U65, PI-13, OP-154 m.3 (ff),
// OP-154 m.3 (t), Ek B 4456, 4457
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_broker_is_a_pep_and_a_revoked_grant_shreds_the_token_set() {
    let mut l = Lab::open("walk-proxy").await;
    l.change(VaultChange::Enable(Box::new(l.resource()))).await;
    let (runtime, instance) = super::super::agent::enrol(&l.w, l.domain).await;
    assert_eq!(
        l.w.plane.instances(l.domain, AGENT).await.unwrap(),
        vec![instance]
    );
    // MD-13
    let parent = issue(
        &l.w,
        l.domain,
        &root_key(&l.w.keys).unwrap(),
        None,
        l.party,
        delegated(&l.action, 1, Some(AGENT)),
        (BTreeSet::from([Capacity::Own]), Capacity::Own),
    )
    .await;
    let held = issue(
        &l.w,
        l.domain,
        &l.person,
        Some(parent),
        AGENT,
        delegated(&l.action, 0, Some(AGENT)),
        (BTreeSet::from([Capacity::For(l.party)]), Capacity::Own),
    )
    .await;

    // AS-M15
    let (status, body, _) = l
        .page(
            &Method::POST,
            "/v1/account/vault/connections",
            Some(serde_json::json!({ "resource": "google", "client_id": l.client })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "vault-consent-required");
    l.consent().await;
    let connection = l
        .connect(r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"token_type":"Bearer"}"#)
        .await;

    // §11.19
    let broker = Broker {
        adp: l.adp.clone(),
        paths: std::sync::Mutex::new(Vec::new()),
    };
    let intent = l.intent(1_200_000);
    let person = l.party;
    let plan = || AgentPlan {
        intent: intent.clone(),
        basis: Some(ExerciseBasis::Holding(held)),
        capacity: Some(Capacity::For(person)),
    };
    let mut first = Exercise::new(l.domain, EXECUTOR, plan(), nonce()).unwrap();
    let Step::Proceed(allowed) = first.ask(&broker, &runtime, &Wall).unwrap() else {
        panic!("allow");
    };
    // EI-26
    let mut as_actor = Exercise::new(l.domain, EXECUTOR, plan(), nonce()).unwrap();
    let stranger = Runtime(suiss_crypto::signer::SoftSigner::generate_p256().unwrap().0);
    let step = as_actor.ask(&broker, &stranger, &Wall).unwrap();
    assert!(!matches!(step, Step::Proceed(_)), "{step:?}");
    // G59, U65
    let (status, r) = l
        .release(
            Some(EXECUTOR),
            &l.body(allowed.exercise(), &intent, &connection, "executor"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["access_token"], "at-1");
    assert!(r["use_until_ms"].as_u64().unwrap() <= intent.validity.until);
    let (_, listed, _) = l
        .page(&Method::GET, "/v1/account/vault/connections", None)
        .await;
    assert_eq!(
        listed["connections"][0]["used"][0]["agent"],
        b64url_encode(&AGENT.0),
        "{listed}"
    );

    // INV-5, MD-13
    let mut pending = Exercise::new(l.domain, EXECUTOR, plan(), nonce()).unwrap();
    let Step::Proceed(waiting) = pending.ask(&broker, &runtime, &Wall).unwrap() else {
        panic!("allow");
    };
    root_revoke(&l.w, l.domain, parent.grant, l.party).await;
    let mut after = Exercise::new(l.domain, EXECUTOR, plan(), nonce()).unwrap();
    let step = after.ask(&broker, &runtime, &Wall).unwrap();
    assert!(matches!(step, Step::Stop(_)), "{step:?}");
    let (status, r) = l
        .release(
            Some(EXECUTOR),
            &l.body(waiting.exercise(), &intent, &connection, "executor"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "release-basis-ended");
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    let id = <[u8; 16]>::try_from(b64url_decode(&connection).unwrap()).unwrap();
    assert!(t.vault_token_set(id).await.unwrap().is_none());
    assert_eq!(
        t.vault_connection(id).await.unwrap().unwrap().status,
        "needs_reconnect"
    );
    t.commit().await.unwrap();

    // PI-13
    for p in broker.paths.lock().unwrap().iter() {
        assert!(standard(p), "{p}");
    }
    l.w.domains.release().await;
}
