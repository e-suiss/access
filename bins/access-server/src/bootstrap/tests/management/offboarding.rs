//! Offboarding through the console's BFF against the real admin surface, sequencer and store
//! (OP-157 m.3 (v), m.6 (a), OP-153 m.3 (gg), §8.17.9.6, E6, X20, Ek B 5447, 5572, 5649): the
//! preview lists every channel of a departing Party with its choices and no default; a commit
//! that leaves a channel without its choice is `422 offboarding-disposition-missing` and changes
//! nothing; a full commit runs the administrator's own signed Exercises in order, ends with the
//! departure, and only then does the Party read as offboarded.

use access_identity_admin::ports::AgentRegistration;
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis, register_nonce,
    self_signed_intent,
};
use access_kernel::claim::body::Class;
use access_kernel::claim::{ClaimState, member_prefix};
use access_kernel::meta::{self as kmeta, ActorKind, GrantBasis, GrantContent, Payload, Root};
use access_kernel::model::{Conjunct, EqValue, Id, SubjectSelector, Window};
use access_store::authority::{state_of, state_prefix};

use super::super::walkthrough::root_commit;
use super::writes::{Written, basis_json};
use super::*;

const LEAVER: Id = Id([0x0d; 16]);

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

fn self_signed(
    (domain, validity): (Digest, Window),
    by: &Browser,
    nonce: &[u8],
    payload: &Payload,
) -> Vec<u8> {
    let intent = self_signed_intent(payload, LEAVER, validity).unwrap();
    let ais = by.ais(
        domain,
        nonce,
        intent_digest(&intent).unwrap(),
        Mode::Commit,
        bootstrap_basis(&domain),
    );
    b64url_decode(&ais).unwrap()
}

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
        party: LEAVER,
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
    r.create.ais = self_signed((c.domain, validity), by, &challenge, &r.create_payload());
    match c.w.plane.register(r).await.unwrap() {
        RegistrationVerdict::Registered(done) => done.instance,
        other @ RegistrationVerdict::Refused { .. } => panic!("{other:?}"),
    }
}

/// The start of the leaver's `operated_by` episode, once the courier recorded its Claim.
async fn episode(c: &Console) -> u64 {
    let d = access_store::scope::DomainId::from_bytes(c.domain.0);
    let courier = super::super::recovery::courier(c);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rows = state_prefix(
            &c.w.db.sequencer,
            &d,
            &member_prefix(&Class::OperatedBy.name(), &LEAVER),
        )
        .await
        .unwrap();
        for r in rows {
            let id = Id::from_bytes(&r.value.unwrap()).unwrap();
            let kept = state_of(&c.w.db.sequencer, &d, &[kmeta::key(kind::CLAIM, &id)])
                .await
                .unwrap();
            if let Some(v) = kept.into_iter().next().and_then(|r| r.value)
                && let Ok(state) = ClaimState::from_bytes(&v)
                && state.ended.is_none()
            {
                return state.since;
            }
        }
        let r = courier.step().await.unwrap();
        assert!(std::time::Instant::now() < deadline, "{r:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One operation of the commit: the meta write `payload` drafted through the BFF and signed by
/// the browser on `basis`.
async fn operation(
    c: &Console,
    (operation, key): (&str, &str),
    payload: serde_json::Value,
    basis: ExerciseBasis,
) -> serde_json::Value {
    let name = payload.as_object().unwrap().keys().next().unwrap().clone();
    let (status, draft) = c
        .draft(&serde_json::json!({
            "action": { "namespace": "access", "name": name, "major": 1 },
            "payload": payload,
            "mode": "commit",
        }))
        .await;
    assert_eq!(status, StatusCode::OK, "{draft}");
    let n = access_crypto::random::bytes::<16>().unwrap();
    let digest = envelope_digest(draft["envelope"].as_str().unwrap());
    serde_json::json!({
        "operation": operation,
        "key": key,
        "body": {
            "ais": c.browser.ais(c.domain, &n, digest, Mode::Commit, basis),
            "intent": draft["intent"],
            "payload": draft["payload"],
            "nonce": b64url_encode(&n),
            "basis": basis_json(basis),
            "capacity": "own",
        },
    })
}

/// Drafts the commit's envelope through the admin surface, signs it and posts the commit.
async fn commit(c: &Console, party: &str, body: &serde_json::Value) -> Written {
    let drafts = "/admin/v1/realms/acme/intents";
    let proof = c.browser.ais(
        c.domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, drafts),
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
                    "operation": "commitOffboarding",
                    "key": party,
                    "body": body,
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    let drafted: serde_json::Value = serde_json::from_slice(&out).unwrap_or_default();
    let digest = if r.status() == StatusCode::OK {
        Digest(
            <[u8; 32]>::try_from(
                b64url_decode(drafted["intent_digest"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
        )
    } else {
        Digest([0x11; 32])
    };
    let n = access_crypto::random::bytes::<16>().unwrap();
    let envelope = c
        .browser
        .ais(c.domain, &n, digest, Mode::Commit, c.idp_anchor());
    let (r, out) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                &format!("/console/api/proxy/admin/realms/acme/offboarding/{party}/commit"),
                "x",
            )
            .header("x-access-ais", envelope)
            .header("idempotency-key", b64url_encode(&n))
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    Written {
        status: r.status(),
        body: serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
    }
}

// OP-157 m.3 (v), m.6 (a), §8.17.9.6, E6, X20, TN-75, OP-153 m.3 (gg), Ek B 5447, 5572, 5649
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "test code: one departure read, refused and committed in order"
)]
async fn offboarding_asks_for_every_channel_and_reads_offboarded_only_after_the_departure() {
    let c = console_with("mgmt-offboard", true, &sample_plan()).await;
    let one_time = key();
    let register = Payload::PartyRegister {
        party: LEAVER,
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
                party: LEAVER,
                operator: c.root,
                key: one_time.key.public_key(),
                register: SelfSigned {
                    ais: self_signed((c.domain, validity), &one_time, &nonce, &register),
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
    let party = b64url_encode(&LEAVER.0);
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/agents",
            ("registerAgent", None),
            serde_json::json!({
                "agent": party,
                "operator": b64url_encode(&c.root.0),
                "agent_kind": "cloud",
                "display_name": "Leaving helper",
                "sponsors": [sponsor],
            }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    let runtimes = [key(), key()];
    let mut instances = Vec::new();
    for k in &runtimes {
        instances.push(instance(&c, k).await);
    }
    let action = sample_plan().sample.unwrap().action_ref();
    let content = |holder| GrantContent {
        basis: GrantBasis::Anchor(kmeta::meta_anchor(&c.domain)),
        holder,
        authority: authority(BTreeSet::from([action.clone()]), "work", BTreeSet::new()),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    };
    let mut direct = Vec::new();
    for _ in 0..2 {
        let (ex, _) = root_commit(
            &c.w,
            c.domain,
            LEAVER,
            Payload::GrantIssue(content(SubjectSelector::Party(LEAVER))),
        )
        .await;
        direct.push(kmeta::object_id(&ex, kind::GRANT, 0));
    }
    // C13
    let (ex, _) = root_commit(
        &c.w,
        c.domain,
        LEAVER,
        Payload::GrantIssue(content(SubjectSelector::Pred(BTreeSet::from([Conjunct {
            claim_class: Class::OperatedBy.name(),
            value: Some(EqValue::Bytes(c.root.0.to_vec())),
        }])))),
    )
    .await;
    let rule = kmeta::object_id(&ex, kind::GRANT, 0);
    episode(&c).await;

    let preview = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/offboarding/{party}/preview"
        ))
        .await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.body);
    let p = &preview.body;
    assert_eq!(p["status"], "active", "{p}");
    assert_eq!(p["survive"], 2, "{p}");
    let listed = |ch: &str, id: &str| -> BTreeSet<String> {
        p["channels"][ch]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m[id].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        listed("grants", "grant"),
        direct.iter().map(|g| b64url_encode(&g.0)).collect()
    );
    assert_eq!(
        listed("instances", "instance"),
        instances.iter().map(|i| b64url_encode(&i.0)).collect()
    );
    assert_eq!(
        listed("holdings", "grant"),
        BTreeSet::from([b64url_encode(&rule.0)])
    );
    // §8.17.9.6: no channel has a default
    assert_eq!(
        p["channels"]["grants"][0]["choices"],
        serde_json::json!(["keep", "revoke"])
    );
    assert_eq!(
        p["channels"]["self_anchor"]["choices"],
        serde_json::json!(["retire", "transfer"])
    );
    let self_anchor = kmeta::object_id(
        &kmeta::exercise_id(&c.domain, &nonce).unwrap(),
        kind::ANCHOR,
        0,
    );
    assert_eq!(
        p["channels"]["self_anchor"]["anchor"],
        b64url_encode(&self_anchor.0)
    );

    let meta = ExerciseBasis::Anchor(kmeta::meta_anchor(&c.domain));
    let own = ExerciseBasis::Anchor(self_anchor);
    let (kept, revoked) = (b64url_encode(&direct[0].0), b64url_encode(&direct[1].0));
    let mut operations = vec![
        operation(
            &c,
            ("revokeGrant", &revoked),
            serde_json::json!({ "grant_revoke": { "grant": revoked } }),
            meta,
        )
        .await,
    ];
    for i in &instances {
        let id = b64url_encode(&i.0);
        operations.push(
            operation(
                &c,
                ("terminateInstance", &id),
                serde_json::json!({ "instance_terminate": { "instance": id } }),
                own,
            )
            .await,
        );
    }
    operations.push(
        operation(
            &c,
            ("departParty", &party),
            serde_json::json!({ "party_depart": { "party": party, "disposition": [] } }),
            meta,
        )
        .await,
    );
    let choices = serde_json::json!({
        "grants": { kept.clone(): "keep", revoked.clone(): "revoke" },
        "instances": instances
            .iter()
            .map(|i| (b64url_encode(&i.0), serde_json::json!("terminate")))
            .collect::<serde_json::Map<_, _>>(),
        "holdings": { b64url_encode(&rule.0): "retain" },
        "self_anchor": "retire",
        "reentry": "blocked",
    });
    let head = c.w.domains.head(c.domain).await.unwrap().0;

    // E6, Ek B 5649
    for drop in ["reentry", "self_anchor", "holdings"] {
        let mut partial = choices.clone();
        partial.as_object_mut().unwrap().remove(drop);
        let r = commit(
            &c,
            &party,
            &serde_json::json!({ "choices": partial, "operations": operations }),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{drop}: {}",
            r.body
        );
        assert_eq!(
            r.body["code"], "offboarding-disposition-missing",
            "{}",
            r.body
        );
    }
    let mut no_choice = choices.clone();
    no_choice["grants"].as_object_mut().unwrap().remove(&kept);
    let r = commit(
        &c,
        &party,
        &serde_json::json!({ "choices": no_choice, "operations": operations }),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    // E6: a revoke chosen without its Exercise carries nothing out
    let r = commit(
        &c,
        &party,
        &serde_json::json!({ "choices": choices, "operations": operations[1..] }),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert_eq!(c.w.domains.head(c.domain).await.unwrap().0, head);
    let still = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/offboarding/{party}/preview"
        ))
        .await;
    assert_eq!(still.body["status"], "active", "{}", still.body);

    let body = serde_json::json!({ "choices": choices, "operations": operations });
    let done = commit(&c, &party, &body).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert_eq!(done.body["exercises"].as_array().unwrap().len(), 4);
    assert_eq!(
        done.body["resource"]["status"], "offboarded",
        "{}",
        done.body
    );
    let after = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/offboarding/{party}/preview"
        ))
        .await;
    assert_eq!(after.body["status"], "offboarded");
    assert_eq!(after.body["departure"]["reentry"], "blocked");
    assert_eq!(after.body["departure"]["choices"]["grants"][&kept], "keep");
    assert!(
        after.body["departed_position"].is_string(),
        "{}",
        after.body
    );
    assert_eq!(after.body["channels"]["instances"], serde_json::json!([]));
    // OP-73: a departed Party is never offboarded twice
    let again = commit(&c, &party, &body).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
}
