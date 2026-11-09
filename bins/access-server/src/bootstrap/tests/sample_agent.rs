//! The local deployment's opt-in sample agent (OP-154 m.15 (i)): the bootstrap registers it
//! with the test user as sponsor, opens its Instance, has the test user's device issue it a
//! Grant for the test user and commits one allowed Exercise; the test user's own hub search
//! then shows it as an agent acting for them, with no executor report, and a second run changes
//! nothing.

use access_http::adp::adapters::{Discovery, Pep as PepId, router as adp_router};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequest, header};
use tower::ServiceExt as _;

use super::*;

fn agent_plan() -> Plan {
    Plan {
        sample_agent: Some(crate::bootstrap::agent::SampleAgentPlan {
            realm: String::from("acme"),
            display_name: String::from("Local sample agent"),
        }),
        ..approve_plan(None)
    }
}

/// One hub search of `kind` by the test user's device Instance, as the account pages sign it.
async fn search(
    adp: &axum::Router,
    domain: Digest,
    device: &HsmSigner,
    party: Id,
    kind: &str,
) -> Vec<serde_json::Value> {
    let now = now_ms();
    let read = IntentEnvelope {
        provenance: BTreeMap::new(),
        action: meta::core_action("read"),
        resources: vec![ResourceRef {
            namespace: String::from("access.search"),
            path: vec![String::from(kind)],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: now - 60_000,
            until: now + 300_000,
        },
    };
    let n = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = bootstrap_basis(&domain);
    let ExerciseBasis::Public(public) = basis else {
        panic!("public basis");
    };
    let ais = sign(
        device,
        &Statement {
            domain,
            nonce: n.clone(),
            intent: intent_digest(&read).unwrap(),
            mode: Mode::Check,
            pep: String::from("access-hub-test"),
            capacity: Capacity::Own,
            basis,
            iat: now,
            exercise: None,
        },
    )
    .unwrap();
    let action = &read.action;
    let body = serde_json::json!({ "context": {
        "domain": b64url_encode(&domain.0),
        "mode": "check",
        "nonce": b64url_encode(&n),
        "intent": {
            "action": { "namespace": action.namespace, "name": action.name, "major": action.major, "schema": b64url_encode(&action.schema.0) },
            "resources": [{ "namespace": "access.search", "path": [kind] }],
            "validity": { "from": read.validity.from, "until": read.validity.until },
        },
        "basis": { "public": b64url_encode(&public.0) },
        "capacity": "own",
        "ais": b64url_encode(&ais),
        "query": { "party": b64url_encode(&party.0) },
    }});
    let mut req = HttpRequest::post(format!("/access/v1/search/{kind}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut()
        .insert(PepId(String::from("access-hub-test")));
    let r = adp.clone().oneshot(req).await.unwrap();
    let status = r.status().as_u16();
    let out: serde_json::Value =
        serde_json::from_slice(&to_bytes(r.into_body(), 1 << 22).await.unwrap()).unwrap();
    assert_eq!(status, 200, "{out}");
    out["results"].as_array().cloned().unwrap_or_default()
}

// OP-154 m.15 (i), m.3 (c), XI-17, A-12, AG-41, INV-4, E64, OP-69, OP-153 m.3 (gg)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bootstrap_makes_a_sample_agent_the_test_user_sees_acting_for_them() {
    let (w, signer) = World::open("bootstrap-sample-agent", true).await;
    let signer = signer.unwrap();
    schedule(&signer);
    schedule(&signer);
    let first = w.run(&agent_plan()).await;
    let json = serde_json::to_value(&first).unwrap();
    let agent = &json["sample_agent"];
    assert_eq!(agent["created"], true, "{json}");
    let party = id_of(agent["party"].as_str().unwrap());
    let person = id_of(json["test_user"]["party"].as_str().unwrap());
    let domain = Digest(
        <[u8; 32]>::try_from(
            access_kernel::json::b64url_decode(json["sample"]["domain"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    );
    // OP-154 m.3 (c), AG-41
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let row = t.agent(party.0).await.unwrap().unwrap();
    assert_eq!(row.display_name, "Local sample agent");
    assert_eq!(
        b64url_encode(&row.operator),
        agent["operator"].as_str().unwrap()
    );
    t.commit().await.unwrap();
    assert_eq!(
        Instances::instances(&w.plane, domain, party).await.unwrap(),
        vec![id_of(agent["instance"].as_str().unwrap())]
    );
    assert_eq!(agent["basis"]["holding"]["holder"], agent["party"]);

    // XI-17, A-12, INV-4, E64
    let adp = adp_router(
        access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
        Discovery {
            issuer: String::from("https://access.test"),
        },
    );
    let pin = Secret::new(String::from(PIN));
    let token = KeyStore::open(&w.module, &w.label, &pin).unwrap();
    let device = token.signer(local::TEST_DEVICE_LABEL).unwrap();
    let inventory = search(&adp, domain, &device, person, "inventory").await;
    let grant = agent["basis"]["holding"]["grant"].clone();
    let acting = inventory
        .iter()
        .find(|r| r["grant"] == grant)
        .unwrap_or_else(|| panic!("{inventory:?}"));
    assert!(
        acting["groups"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::from("acting_for_you")),
        "{acting}"
    );
    assert_eq!(acting["agent"]["party_kind"], "agent", "{acting}");
    let activity = search(&adp, domain, &device, person, "activity").await;
    let used = activity
        .iter()
        .find(|u| u["exercise"] == agent["exercise"])
        .unwrap_or_else(|| panic!("{activity:?}"));
    assert_eq!(used["agent"]["party_kind"], "agent", "{used}");
    assert_eq!(used["agent"]["party"], agent["party"], "{used}");
    assert!(
        used["reports"]["attested"].as_array().unwrap().is_empty(),
        "{used}"
    );
    w.domains.release().await;

    // OP-69
    let second = serde_json::to_value(w.run(&agent_plan()).await).unwrap();
    assert_eq!(second["sample_agent"]["created"], false, "{second}");
    for k in ["party", "instance", "basis", "exercise"] {
        assert_eq!(second["sample_agent"][k], agent[k], "{k}");
    }
}

// OP-154 m.15 (i), OP-69
#[test]
fn a_sample_agent_needs_the_sample_and_its_sponsor_in_its_realm() {
    let dir = std::env::temp_dir().join(format!("abs-sample-agent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let plan = |name: &str, body: &str| {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!("platform = 'platform'\ntenants = ['acme']\n{body}"),
        )
        .unwrap();
        Plan::load(&path)
    };
    let sample = "[sample]\nrealm = 'acme'\nnamespace = 'work'\naction = 'approve'\n";
    let user = "[test_user]\nrealm = 'acme'\nidentifier = 'test@acme.example'\nredirect_uri = 'http://127.0.0.1/cb'\npassword = 'correct horse battery staple'\n";
    let agent = "[sample_agent]\nrealm = 'acme'\n";
    assert!(plan("no-user", &format!("{sample}{agent}")).is_err());
    assert!(plan("no-sample", &format!("{user}{agent}")).is_err());
    assert!(
        plan(
            "long",
            &format!(
                "{sample}{user}[sample_agent]\nrealm = 'acme'\ndisplay_name = '{}'\n",
                "x".repeat(201)
            )
        )
        .is_err()
    );
    let ok = plan("ok", &format!("{sample}{user}{agent}")).unwrap();
    assert_eq!(ok.sample_agent.unwrap().display_name, "Local sample agent");
}
