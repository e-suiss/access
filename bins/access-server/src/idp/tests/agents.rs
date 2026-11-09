//! Agents through commit against real PostgreSQL, the sequencer and the authority plane
//! (OP-154 m.3 (c), (e), (g), RR-12, AG-19, AG-41): an agent is its own Party rooted in its
//! operator, the realm issuer exports it as Claims, it acts only through a template's Grant
//! inside its budget and depth, and the sponsor rule holds on the real commit.

use access_authority_core::domain::{ProofRef, Request};
use access_identity_account::domain::claims::agent_line;
use access_identity_admin::app::rest::{Op, compile};
use access_identity_admin::domain::Invalid;
use access_identity_admin::domain::agent::{
    AgentChange, AgentKind, AgentRegister, AgentTemplate, AgentUpdate, Placement, Sponsor,
    sponsor_required,
};
use access_internal_api::idp::{IdpAction, Verdict};
use access_internal_api::instances::{RegistrationVerdict, SelfSigned};
use access_kernel::claim::body::Class;
use access_kernel::combinator::{BlockerClass, Outcome};
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{ActorKind, GrantBasis, HoldingRef, Payload, Root};
use access_kernel::model::SubjectSelector;
use access_store::issuer::{last_in_line, realm_issuer};
use serde_json::json;

use super::claims::courier;
use super::*;

const AGENT: Id = Id([0x0b; 16]);
const AGENT_ONE_TIME: u8 = 0x3b;
const AGENT_KEY: u8 = 0x4b;
const HELPER: Id = Id([0x0c; 16]);
const HELPER_ONE_TIME: u8 = 0x3c;
const HELPER_KEY: u8 = 0x4c;
const SLUG: &str = "agents";

/// The `party_register` of agent `party` rooted in `operator`, signed by the one-time key
/// `seed` its operator's client made (OP-154 m.3 (c)).
fn agent_register(d: Digest, party: Id, operator: Id, seed: u8) -> SelfSigned {
    let payload = Payload::PartyRegister {
        party,
        root: Root::Sole(operator),
        actor_kind: ActorKind::Agent,
    };
    let nonce = register_nonce(&challenge_of(seed));
    SelfSigned {
        ais: self_signed(d, &nonce, &payload, party, seed),
        nonce,
        validity: Window {
            from: 0,
            until: HOUR,
        },
    }
}

struct Ready {
    w: World,
    at: (TenantId, RealmId),
    d: Digest,
    issuer: Id,
    sponsor: [u8; 16],
}

/// A realm whose root ROOT is bound to a founder account, and a second account bound to ALICE
/// that sponsors agents.
async fn ready() -> Ready {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm(SLUG).await;
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    w.admin().register_issuer(tenant, realm).await.unwrap();
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let founder = t
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    let sponsor = t
        .insert_subject("active", "realm-kek:1", &[8; 40])
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &founder, &ROOT.0)
            .await
            .unwrap()
    );
    assert!(
        access_store::idp::bind_subject_party(&mut t, &sponsor, &ALICE.0)
            .await
            .unwrap()
    );
    let issuer = Id(realm_issuer(&mut t).await.unwrap().unwrap());
    t.commit().await.unwrap();
    Ready {
        w,
        at: (tenant, realm),
        d,
        issuer,
        sponsor,
    }
}

/// Steps the claim courier until `n` more orders have been answered.
async fn settle(r: &Ready, n: u32) {
    let c = courier(&r.w);
    let mut answered = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while answered < n {
        let report = c.step().await.unwrap();
        answered += report.answered;
        assert_eq!(report.unplaced, 0, "{report:?}");
        assert!(std::time::Instant::now() < deadline, "{answered} of {n}");
        if report.answered == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Registers agent `party` of operator ROOT with `sponsors`, issues its Claims and opens the
/// Instance of the runtime key `key` (OP-154 m.3 (c)).
async fn agent(r: &Ready, (party, one_time, key): (Id, u8, u8), nonce: u8, sponsors: &[[u8; 16]]) {
    assert!(
        !r.w.admin()
            .register_agent(
                r.at,
                (party, ROOT),
                public(one_time),
                agent_register(r.d, party, ROOT, one_time),
            )
            .await
            .unwrap()
    );
    let change = Change::Agent(AgentChange::Register(AgentRegister {
        party: party.0,
        operator: ROOT.0,
        kind: AgentKind::Cloud,
        display_name: String::from("Mail helper"),
        description: None,
        sponsors: sponsors.to_vec(),
    }));
    let p = proposal(r.at, change, nonce, idp_anchor(r.d), 1);
    written(&exercise(&r.w, &p, ROOT_KEY).await.unwrap());
    settle(r, 2 + u32::try_from(sponsors.len()).unwrap()).await;
    let v = Instances::register(&r.w.plane, registration(r.d, device(), party, key, false))
        .await
        .unwrap();
    assert!(matches!(v, RegistrationVerdict::Registered(_)), "{v:?}");
}

fn template() -> AgentTemplate {
    AgentTemplate {
        name: access_identity_admin::domain::Name::parse("mail-helper").unwrap(),
        actions: std::collections::BTreeSet::from([IdpAction::AgentUpdate.action_ref()]),
        namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
        prefix: vec![String::from(SLUG), String::from("agent")],
        consumption: false,
        spend: None,
        count: 10,
        window_s: 3_600,
        depth: 1,
        ttl_ms: HOUR,
    }
}

/// The ROOT-issued Grant from the template to `agent` (RR-12: the user's own `grant_issue`).
async fn grant(r: &Ready, agent: Id, nonce: u8) -> ExerciseBasis {
    let idp = meta::object_id(
        &r.d,
        kind::ANCHOR,
        access_authority_core::genesis::IDP_ANCHOR,
    );
    let content = template().grant(&Placement {
        basis: GrantBasis::Anchor(idp),
        agent,
        operator: ROOT,
        issuer: r.issuer,
        from: 0,
    });
    let (intent, payload) = meta_intent(Payload::GrantIssue(content));
    let v = commit(
        r,
        nonce,
        (intent, Some(payload)),
        ExerciseBasis::Anchor(idp),
        ROOT_KEY,
        &[],
    )
    .await;
    let Verdict::Committed(c) = v else {
        panic!("{v:?}");
    };
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&c.exercise, kind::GRANT, 0),
        holder: agent,
        since: c.position,
    })
}

fn meta_intent(payload: Payload) -> (IntentEnvelope, Payload) {
    let intent = IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: meta::core_action(payload.action()),
        resources: vec![access_kernel::model::ResourceRef {
            namespace: String::from("access.party"),
            path: vec![String::from("p")],
            incarnation: 0,
        }],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::from([(
            String::from(meta::PAYLOAD_PARAM),
            payload.digest().unwrap(),
        )]),
        recipient: None,
        purpose: None,
        context: access_kernel::intent::ContextRefs::default(),
        validity: Window {
            from: NOW,
            until: NOW + HOUR,
        },
    };
    (intent, payload)
}

/// Commits `intent` on `basis` signed by the key `seed`, presenting `claims` by reference, as
/// the identity plane's PEP on the real decision point.
async fn commit(
    r: &Ready,
    nonce: u8,
    (intent, payload): (IntentEnvelope, Option<Payload>),
    basis: ExerciseBasis,
    seed: u8,
    claims: &[[u8; 16]],
) -> Verdict {
    let digest = intent_digest(&intent).unwrap();
    let ais = sign(&statement(r.d, &[nonce; 16], digest, basis), seed);
    r.w.plane
        .commit(
            Request {
                domain: r.d,
                mode: Mode::Commit,
                nonce: vec![nonce; 16],
                intent,
                payload,
                basis,
                capacity: Capacity::Own,
                proofs: claims.iter().map(|c| ProofRef::ClaimRef(Id(*c))).collect(),
                exercise: None,
                consistency: None,
            },
            ais,
            (String::from(PEP), None),
        )
        .await
        .unwrap()
}

/// The intent of the agent renaming itself: the action its Grant covers.
fn rename(agent: Id) -> IntentEnvelope {
    Change::Agent(AgentChange::Update(AgentUpdate {
        agent: agent.0,
        display_name: String::from("Renamed"),
        description: None,
    }))
    .intent(
        SLUG,
        Window {
            from: NOW,
            until: NOW + HOUR,
        },
    )
    .unwrap()
}

/// The last Claim the realm issuer issued on `agent`'s `class` line about `about`.
async fn claim_of(r: &Ready, agent: Id, class: Class, about: &[u8]) -> [u8; 16] {
    let mut t = TenantTx::begin(&r.w.db.app, r.at.0, r.at.1).await.unwrap();
    let id = last_in_line(
        &mut t,
        &agent.0,
        &DomainId::from_bytes(r.d.0),
        &agent_line(&agent.0, class, about),
    )
    .await
    .unwrap()
    .unwrap();
    t.commit().await.unwrap();
    id
}

fn allowed(v: &Verdict) {
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
}

fn denied(v: &Verdict) -> &access_kernel::combinator::Decision {
    match v {
        Verdict::NotAllowed { decision, .. } if decision.outcome == Outcome::Deny => decision,
        other => panic!("{other:?}"),
    }
}

// OP-154 m.3 (c), AG-19, AG-20, F15, F18, I2, E23, Ek B 4266, 4317, 4318, 4319, 4320, 4375
#[tokio::test]
async fn an_agent_is_its_own_party_and_the_realm_issuer_exports_it_as_claims() {
    let r = Box::pin(ready()).await;
    agent(&r, (AGENT, AGENT_ONE_TIME, AGENT_KEY), 1, &[r.sponsor]).await;
    assert_eq!(
        Instances::party(&r.w.plane, r.d, AGENT).await.unwrap(),
        Some(access_identity_admin::ports::PartyKind {
            actor_kind: ActorKind::Agent,
            ended: false,
        })
    );
    // AG-21
    let instances =
        r.w.admin()
            .agent_instances(r.at, AGENT.0)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(instances.len(), 1);
    let mut t = TenantTx::begin(&r.w.db.app, r.at.0, r.at.1).await.unwrap();
    let row = t.agent(AGENT.0).await.unwrap().unwrap();
    assert_eq!(
        (row.kind.as_str(), row.status.as_str()),
        ("cloud", "active")
    );
    assert_eq!(row.operator, ROOT.0);
    t.commit().await.unwrap();
    // AG-20
    for (class, about) in [
        (Class::OperatedBy, &[][..]),
        (Class::AgentKind, &[][..]),
        (Class::SponsoredBy, &r.sponsor[..]),
    ] {
        claim_of(&r, AGENT, class, about).await;
    }
    // OP-154 m.3 (c)
    let not_agent = Change::Agent(AgentChange::Register(AgentRegister {
        party: ALICE.0,
        operator: ROOT.0,
        kind: AgentKind::Local,
        display_name: String::from("Not an agent"),
        description: None,
        sponsors: vec![r.sponsor],
    }));
    let p = proposal(r.at, not_agent, 2, idp_anchor(r.d), 1);
    assert!(matches!(
        r.w.admin().prepare(&p).await,
        Err(AdminError::Invalid(Invalid::Agent))
    ));
}

// RR-12, AG-41, OP-154 m.3 (e), (g), SI-21, IDP-35, X13, Ek B 4334, 4381, 4514, 4614
#[tokio::test]
async fn an_agent_acts_only_through_its_grant_and_waits_for_a_sponsor_when_the_last_leaves() {
    let r = Box::pin(ready()).await;
    agent(&r, (AGENT, AGENT_ONE_TIME, AGENT_KEY), 1, &[r.sponsor]).await;
    let define = Change::Agent(AgentChange::TemplateDefine(template()));
    written(
        &exercise(
            &r.w,
            &proposal(r.at, define, 3, idp_anchor(r.d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let holding = grant(&r, AGENT, 4).await;
    let sponsored = claim_of(&r, AGENT, Class::SponsoredBy, &r.sponsor).await;

    allowed(
        &commit(
            &r,
            5,
            (rename(AGENT), None),
            holding,
            AGENT_KEY,
            &[sponsored],
        )
        .await,
    );

    // RR-12, EI-6
    let idp = meta::object_id(
        &r.d,
        kind::ANCHOR,
        access_authority_core::genesis::IDP_ANCHOR,
    );
    let wider = template().grant(&Placement {
        basis: GrantBasis::Anchor(idp),
        agent: AGENT,
        operator: ROOT,
        issuer: r.issuer,
        from: 0,
    });
    let self_issue = commit(
        &r,
        6,
        {
            let (i, p) = meta_intent(Payload::GrantIssue(wider));
            (i, Some(p))
        },
        ExerciseBasis::Anchor(idp),
        AGENT_KEY,
        &[sponsored],
    )
    .await;
    denied(&self_issue);
    let retire = Change::Agent(AgentChange::Retire(AGENT.0))
        .intent(
            SLUG,
            Window {
                from: NOW,
                until: NOW + HOUR,
            },
        )
        .unwrap();
    let outside = commit(&r, 7, (retire, None), holding, AGENT_KEY, &[sponsored]).await;
    assert_eq!(
        denied(&outside).blockers[0].class,
        BlockerClass::NoCoveringAuthority
    );

    // OP-154 m.3 (e)
    let remove = compile(
        Op::RemoveAgentSponsor,
        Some(&format!(
            "{}:{}",
            access_kernel::json::b64url_encode(&AGENT.0),
            r.w.ids
                .encode(access_identity_account::app::SUBJECT_PREFIX, r.sponsor)
                .unwrap()
        )),
        &json!({}),
        &r.w.ids,
    )
    .unwrap();
    written(
        &exercise(
            &r.w,
            &proposal(r.at, remove, 8, idp_anchor(r.d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    settle(&r, 1).await;
    let waiting = commit(
        &r,
        9,
        (rename(AGENT), None),
        holding,
        AGENT_KEY,
        &[sponsored],
    )
    .await;
    let Verdict::NotAllowed { decision, .. } = &waiting else {
        panic!("{waiting:?}");
    };
    assert!(sponsor_required(decision), "{decision:?}");
    let mut t = TenantTx::begin(&r.w.db.app, r.at.0, r.at.1).await.unwrap();
    assert_eq!(t.agent(AGENT.0).await.unwrap().unwrap().status, "suspended");
    // SI-21
    let episodes = t.sponsorships(AGENT.0).await.unwrap();
    assert_eq!(episodes.len(), 1);
    assert_eq!(episodes[0].ended_by.as_deref(), Some("remove"));
    assert!(episodes[0].ended.is_some());
    t.commit().await.unwrap();
    let events = identity_events(&r.w.db, "event.agent.", 2).await;
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"event.agent.sponsor_assigned"), "{kinds:?}");
    assert!(kinds.contains(&"event.agent.suspended"), "{kinds:?}");

    let assign = Change::Agent(AgentChange::SponsorAssign(Sponsor {
        agent: AGENT.0,
        subject: r.sponsor,
    }));
    written(
        &exercise(
            &r.w,
            &proposal(r.at, assign, 10, idp_anchor(r.d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    settle(&r, 1).await;
    let renewed = claim_of(&r, AGENT, Class::SponsoredBy, &r.sponsor).await;
    assert_ne!(renewed, sponsored);
    allowed(
        &commit(
            &r,
            11,
            (rename(AGENT), None),
            holding,
            AGENT_KEY,
            &[renewed],
        )
        .await,
    );
    let mut t = TenantTx::begin(&r.w.db.app, r.at.0, r.at.1).await.unwrap();
    assert_eq!(t.agent(AGENT.0).await.unwrap().unwrap().status, "active");
    t.commit().await.unwrap();
}

// C15, OP-154 m.3 (g), §9.9.4, §13.7.6, Ek B 4267, 4335, 4336
#[tokio::test]
async fn an_agent_delegates_one_hop_to_its_operators_agents_and_no_further() {
    let r = Box::pin(ready()).await;
    agent(&r, (AGENT, AGENT_ONE_TIME, AGENT_KEY), 1, &[r.sponsor]).await;
    agent(&r, (HELPER, HELPER_ONE_TIME, HELPER_KEY), 2, &[r.sponsor]).await;
    let holding = grant(&r, AGENT, 3).await;
    let sponsored = claim_of(&r, AGENT, Class::SponsoredBy, &r.sponsor).await;
    let ExerciseBasis::Holding(h) = holding else {
        panic!("holding");
    };
    let mut onward = template().grant(&Placement {
        basis: GrantBasis::Holding(h),
        agent: HELPER,
        operator: ROOT,
        issuer: r.issuer,
        from: 0,
    });
    onward.authority.delegation.depth = 0;
    // C15
    onward.holder = SubjectSelector::Pred(std::collections::BTreeSet::from([
        access_kernel::model::Conjunct {
            claim_class: Class::OperatedBy.name(),
            value: Some(access_kernel::model::EqValue::Bytes(ROOT.0.to_vec())),
        },
    ]));
    let delegated = commit(
        &r,
        4,
        {
            let (i, p) = meta_intent(Payload::GrantIssue(onward.clone()));
            (i, Some(p))
        },
        holding,
        AGENT_KEY,
        &[sponsored],
    )
    .await;
    let Verdict::Committed(c) = &delegated else {
        panic!("{delegated:?}");
    };
    let second = HoldingRef {
        grant: meta::object_id(&c.exercise, kind::GRANT, 0),
        holder: HELPER,
        since: c.position,
    };
    let mut again = onward;
    again.basis = GrantBasis::Holding(second);
    again.holder = SubjectSelector::Party(AGENT);
    let helper_claim = claim_of(&r, HELPER, Class::SponsoredBy, &r.sponsor).await;
    let deeper = commit(
        &r,
        5,
        {
            let (i, p) = meta_intent(Payload::GrantIssue(again));
            (i, Some(p))
        },
        ExerciseBasis::Holding(second),
        HELPER_KEY,
        &[helper_claim],
    )
    .await;
    denied(&deeper);
    let mut stranger = template().grant(&Placement {
        basis: GrantBasis::Holding(h),
        agent: ALICE,
        operator: ROOT,
        issuer: r.issuer,
        from: 0,
    });
    stranger.authority.delegation.depth = 0;
    let other = commit(
        &r,
        6,
        {
            let (i, p) = meta_intent(Payload::GrantIssue(stranger));
            (i, Some(p))
        },
        holding,
        AGENT_KEY,
        &[sponsored],
    )
    .await;
    denied(&other);
    // X10
    let unbudgeted = compile(
        Op::DefineAgentTemplate,
        None,
        &json!({
            "name": "spender",
            "actions": [{ "namespace": "idp.agent", "name": "update", "major": 1 }],
            "resource": { "namespace": "idp", "prefix": [SLUG] },
            "consumption": true,
            "count": { "capacity": 5, "window_s": 3600 },
            "ttl_s": 3600,
        }),
        &r.w.ids,
    )
    .unwrap();
    let p = proposal(r.at, unbudgeted, 7, idp_anchor(r.d), 1);
    assert!(matches!(
        r.w.admin().prepare(&p).await,
        Err(AdminError::Invalid(Invalid::AgentTemplate))
    ));
}

// AG-36, AGI-7, CI-2, §9.4.2, §11.17, E23, E55, Ek B 4338, 4339, 4341, 4383, 4604
#[tokio::test]
async fn a_trust_score_claim_never_meets_a_grant_requirement_or_stands_for_a_grant() {
    let r = Box::pin(ready()).await;
    agent(&r, (AGENT, AGENT_ONE_TIME, AGENT_KEY), 1, &[r.sponsor]).await;
    let holding = grant(&r, AGENT, 2).await;
    let operated = claim_of(&r, AGENT, Class::OperatedBy, &[]).await;
    let kind_claim = claim_of(&r, AGENT, Class::AgentKind, &[]).await;
    let scored = commit(
        &r,
        3,
        (rename(AGENT), None),
        holding,
        AGENT_KEY,
        &[operated, kind_claim],
    )
    .await;
    let Verdict::NotAllowed { decision, .. } = &scored else {
        panic!("{scored:?}");
    };
    assert_eq!(decision.outcome, Outcome::RequireAction);
    assert!(sponsor_required(decision));
    let sponsored = claim_of(&r, AGENT, Class::SponsoredBy, &r.sponsor).await;
    let none = commit(
        &r,
        4,
        (rename(AGENT), None),
        idp_anchor(r.d),
        AGENT_KEY,
        &[sponsored, operated, kind_claim],
    )
    .await;
    denied(&none);
}
