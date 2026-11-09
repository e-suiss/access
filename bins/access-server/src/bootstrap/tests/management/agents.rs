//! The agent registry through the console's BFF against the real admin surface (OP-154 m.3 (c),
//! (e), (f), OP-153 m.3 (gg), Ek B 4382, 4386, 4475, 4510): an agent registered by REST is read
//! back with its sponsors and Instances, and `revoke-all` ends every Instance as one signed
//! `instance_terminate` each, after which none of its keys acts.

use access_identity_admin::ports::AgentRegistration;
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis, register_nonce,
    self_signed_intent,
};
use access_kernel::meta::{self as kmeta, ActorKind, Payload, Root};
use access_kernel::model::{Id, Window};

use super::writes::basis_json;
use super::*;

const AGENT: Id = Id([0x0b; 16]);

fn key() -> Browser {
    Browser {
        jar: Vec::new(),
        csrf: String::new(),
        key: SoftSigner::generate_p256().unwrap().0,
    }
}

fn window() -> Window {
    Window {
        from: now() - 60_000,
        until: now() + 600_000,
    }
}

/// The AIS by `by`'s key over the self-signed `payload` of `party` under the bootstrap basis.
fn self_signed(
    (domain, validity): (Digest, Window),
    by: &Browser,
    nonce: &[u8],
    payload: &Payload,
    party: Id,
) -> Vec<u8> {
    let intent = self_signed_intent(payload, party, validity).unwrap();
    let ais = by.ais(
        domain,
        nonce,
        intent_digest(&intent).unwrap(),
        Mode::Commit,
        bootstrap_basis(&domain),
    );
    b64url_decode(&ais).unwrap()
}

/// Opens an Instance of the agent for the runtime key `by` (OP-154 m.3 (c)).
async fn instance(c: &Console, by: &Browser) -> Id {
    let challenge = access_crypto::random::bytes::<32>().unwrap().to_vec();
    let validity = window();
    let mut r = Registration {
        tenant: *c.route.tenant.as_bytes(),
        domain: c.domain,
        registrant: Registrant::Device {
            realm: *c.route.realm.as_bytes(),
            subject: c.subject,
        },
        party: AGENT,
        key: by.key.public_key(),
        register: None,
        create: SelfSigned {
            nonce: challenge.clone(),
            validity,
            ais: Vec::new(),
        },
        pep: String::from(access_identity_ui::domain::frontend::IDENTITY_PEP),
        context: None,
    };
    r.create.ais = self_signed(
        (c.domain, validity),
        by,
        &challenge,
        &r.create_payload(),
        AGENT,
    );
    match c.w.plane.register(r).await.unwrap() {
        RegistrationVerdict::Registered(done) => done.instance,
        other @ RegistrationVerdict::Refused { .. } => panic!("{other:?}"),
    }
}

// OP-154 m.3 (c), (e), (f), P59, AG-21, AG-41, OP-153 m.3 (gg), Ek B 4382, 4386, 4475, 4510
#[tokio::test]
async fn the_registry_lists_an_agent_and_revoke_all_ends_every_instance() {
    let c = console("mgmt-agents", true).await;
    let one_time = key();
    let register = Payload::PartyRegister {
        party: AGENT,
        root: Root::Sole(c.root),
        actor_kind: ActorKind::Agent,
    };
    let nonce = register_nonce(&access_crypto::random::bytes::<32>().unwrap());
    let validity = window();
    let registered =
        c.w.plane
            .register_agent(AgentRegistration {
                tenant: *c.route.tenant.as_bytes(),
                domain: c.domain,
                party: AGENT,
                operator: c.root,
                key: one_time.key.public_key(),
                register: SelfSigned {
                    ais: self_signed((c.domain, validity), &one_time, &nonce, &register, AGENT),
                    nonce: nonce.clone(),
                    validity,
                },
                pep: String::from(access_identity_ui::domain::frontend::IDENTITY_PEP),
            })
            .await
            .unwrap();
    assert!(
        matches!(
            registered,
            access_identity_admin::ports::OrgRegistered::Registered { .. }
        ),
        "{registered:?}"
    );
    let accounts = c.admin_get("/admin/v1/realms/acme/accounts").await;
    let sponsor = accounts.body["items"][0]["account_id"].clone();
    let agent = b64url_encode(&AGENT.0);
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/agents",
            ("registerAgent", None),
            serde_json::json!({
                "agent": agent,
                "operator": b64url_encode(&c.root.0),
                "agent_kind": "cloud",
                "display_name": "Mail helper",
                "sponsors": [sponsor],
            }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    assert_eq!(w.body["resource"]["agent"], agent, "{}", w.body);

    let runtimes = [key(), key()];
    let mut instances = Vec::new();
    for k in &runtimes {
        instances.push(instance(&c, k).await);
    }
    let list = c.admin_get("/admin/v1/realms/acme/agents").await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    assert_eq!(list.body["items"][0]["agent"], agent);
    let one = c
        .admin_get(&format!("/admin/v1/realms/acme/agents/{agent}"))
        .await;
    assert_eq!(one.status, StatusCode::OK, "{}", one.body);
    assert_eq!(one.body["status"], "active");
    assert_eq!(one.body["sponsors"][0], sponsor);
    assert_eq!(one.body["connections"], serde_json::json!([]));
    assert_eq!(one.body["instances"].as_array().unwrap().len(), 2);
    let sponsors = c
        .admin_get(&format!("/admin/v1/realms/acme/agents/{agent}/sponsors"))
        .await;
    assert_eq!(sponsors.body["items"][0]["account_id"], sponsor);

    // OP-154 m.3 (f)
    let anchor = kmeta::object_id(
        &kmeta::exercise_id(&c.domain, &nonce).unwrap(),
        kind::ANCHOR,
        0,
    );
    let basis = ExerciseBasis::Anchor(anchor);
    let mut operations = Vec::new();
    for i in &instances {
        let payload =
            serde_json::json!({ "instance_terminate": { "instance": b64url_encode(&i.0) } });
        let (status, draft) = c
            .draft(&serde_json::json!({
                "action": { "namespace": "access", "name": "instance_terminate", "major": 1 },
                "payload": payload,
                "mode": "commit",
            }))
            .await;
        assert_eq!(status, StatusCode::OK, "{draft}");
        let n = access_crypto::random::bytes::<16>().unwrap();
        let digest = envelope_digest(draft["envelope"].as_str().unwrap());
        let ais = c.browser.ais(c.domain, &n, digest, Mode::Commit, basis);
        operations.push(serde_json::json!({
            "operation": "terminateAgentInstance",
            "key": format!("{agent}:{}", b64url_encode(&i.0)),
            "body": {
                "ais": ais,
                "intent": draft["intent"],
                "payload": draft["payload"],
                "nonce": b64url_encode(&n),
                "basis": basis_json(basis),
                "capacity": "own",
            },
        }));
    }
    let job = serde_json::json!({ "mode": "parallel", "operations": operations });
    let partial = serde_json::json!({ "mode": "parallel", "operations": [operations[0].clone()] });
    for (body, ok) in [(partial, false), (job, true)] {
        let proof = c.browser.ais(
            c.domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::POST, "/admin/v1/realms/acme/intents"),
            Mode::Check,
            c.idp_anchor(),
        );
        let (r, out) = send(
            &c.management,
            c.browser
                .request(
                    &Method::POST,
                    "/console/api/proxy/admin/realms/acme/intents",
                    "x",
                )
                .header("x-access-ais", proof)
                .body(Body::from(
                    serde_json::json!({
                        "operation": "revokeAllAgentInstances",
                        "key": agent,
                        "body": body,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&out)
        );
        let drafted: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let digest = Digest(
            <[u8; 32]>::try_from(
                b64url_decode(drafted["intent_digest"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
        );
        let n = access_crypto::random::bytes::<16>().unwrap();
        let envelope = c
            .browser
            .ais(c.domain, &n, digest, Mode::Commit, c.idp_anchor());
        let (r, out) = send(
            &c.management,
            c.browser
                .request(
                    &Method::POST,
                    &format!("/console/api/proxy/admin/realms/acme/agents/{agent}/revoke-all"),
                    "x",
                )
                .header("x-access-ais", envelope)
                .header("idempotency-key", b64url_encode(&n))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        if !ok {
            assert_eq!(
                r.status(),
                StatusCode::BAD_REQUEST,
                "{}",
                String::from_utf8_lossy(&out)
            );
            continue;
        }
        assert_eq!(
            r.status(),
            StatusCode::ACCEPTED,
            "{}",
            String::from_utf8_lossy(&out)
        );
        let id = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["job_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut done = serde_json::Value::Null;
        for _ in 0..2_000 {
            done = c
                .admin_get(&format!("/admin/v1/realms/acme/jobs/{id}"))
                .await
                .body;
            if done["status"] != "running" {
                break;
            }
            tokio::task::yield_now().await;
        }
        let items = c
            .admin_get(&format!("/admin/v1/realms/acme/jobs/{id}/items"))
            .await
            .body;
        assert_eq!(done["status"], "succeeded", "{done} {items}");
        assert_eq!(done["committed"], 2, "{done}");
    }
    let after = c
        .admin_get(&format!("/admin/v1/realms/acme/agents/{agent}"))
        .await;
    assert_eq!(
        after.body["instances"],
        serde_json::json!([]),
        "{}",
        after.body
    );
    // P59, §9.16.2 k.5, Ek B 4387, 4388
    let events: Vec<_> = access_store::authority::read_outbox(
        &c.w.db.app,
        &access_store::scope::DomainId::from_bytes(c.domain.0),
        (0, 0),
        1_000,
    )
    .await
    .unwrap()
    .iter()
    .map(|r| access_internal_api::events::Event::from_bytes(&r.event).unwrap())
    .filter(|e| e.kind == access_internal_api::events::Kind::InstanceTerminated)
    .collect();
    for i in &instances {
        assert!(
            events
                .iter()
                .any(|e| e.subject == access_internal_api::events::Subject::Instance(*i)),
            "{events:?}"
        );
    }
    for k in &runtimes {
        let ais = k.ais(
            c.domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            Digest([7; 32]),
            Mode::Commit,
            c.idp_anchor(),
        );
        let signer = access_identity_admin::ports::Decider::signer(
            &c.w.plane,
            c.domain,
            &b64url_decode(&ais).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(signer, None);
    }
}
