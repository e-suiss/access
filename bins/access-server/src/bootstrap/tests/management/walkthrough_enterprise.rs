//! Enterprise agent (§11.19): a workload Party of the company's domain, registered by REST
//! with its operator and sponsor, whose runtime presents a JWT-SVID at the token endpoint and
//! opens its own Instance on the realm issuer's `identity_binding_workload` Claim; a rule-shaped
//! Grant whose holder is a predicate over the `operated_by` Claim; the company's PEP asks the
//! ADP; and deprovisioning the agent withdraws its Claims, after which the same request fails
//! closed at ingest.

use access_kernel::claim::body::Class;
use access_kernel::claim::{ClaimState, member_prefix};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{self as kmeta, GrantBasis, GrantContent, HoldingRef, Payload};
use access_kernel::model::{ActionRef, Conjunct, EqValue, Id, ResourceRef, SubjectSelector};
use access_sdk::agent::contract::{Exercise, Plan as AgentPlan, Step};
use access_store::authority::{state_of, state_prefix};
use suiss_crypto::signer::SoftSigner;

use super::super::agent::{AGENT_PEP, Runtime, Wall, nonce};
use super::super::walkthrough::{Recorded, root_commit};
use super::workloads::{
    AGENT, BUNDLE, WORKLOAD, agent, bundle, issued, open, present, signer, svid, workload_client,
};
use super::*;

fn intent(action: &ActionRef, path: &str) -> IntentEnvelope {
    IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: action.clone(),
        resources: vec![ResourceRef {
            namespace: String::from("work"),
            path: vec![String::from(path)],
            incarnation: 0,
        }],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: now() - 60_000,
            until: now() + 600_000,
        },
    }
}

/// The start of AGENT's `operated_by` episode as the domain recorded it: the position of its
/// live Claim, which a holding of a predicate-held Grant names as `since` (OP-141 m.20); the
/// courier is stepped until the Claim is there.
async fn episode(c: &Console) -> u64 {
    let d = access_store::scope::DomainId::from_bytes(c.domain.0);
    let courier = super::super::recovery::courier(c);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rows = state_prefix(
            &c.w.db.sequencer,
            &d,
            &member_prefix(&Class::OperatedBy.name(), &AGENT),
        )
        .await
        .unwrap();
        let mut since = None;
        for r in rows {
            let id = Id::from_bytes(&r.value.unwrap()).unwrap();
            let kept = state_of(&c.w.db.sequencer, &d, &[kmeta::key(kind::CLAIM, &id)])
                .await
                .unwrap();
            if let Some(v) = kept.into_iter().next().and_then(|r| r.value) {
                let state = ClaimState::from_bytes(&v).unwrap();
                if state.ended.is_none() {
                    since = Some(since.map_or(state.since, |s: u64| s.min(state.since)));
                }
            }
        }
        if let Some(s) = since {
            return s;
        }
        let r = courier.step().await.unwrap();
        assert!(std::time::Instant::now() < deadline, "{r:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// §11.19, U20, AG-30, L25, C15, INV-23, OP-154 m.3 (c), (d), (r), (ff), PI-13, Ek B 4454, 4457
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enterprise_workload_acts_on_a_rule_shaped_grant_until_it_is_deprovisioned() {
    let c = console_with("walk-enterprise", true, &sample_plan()).await;
    // U20, AG-30
    agent(&c).await;
    let td = signer();
    c.bundles.serve(BUNDLE, &bundle(&td.key));
    let w = workload_client(&c, "spiffe://acme.example/agent/mail/*", BUNDLE).await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    let runtime = signer();
    c.trust
        .scripted
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, body, _) = present(&c, &|| svid(&td.key, WORKLOAD), &runtime.key).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");
    issued(&c, &runtime.key.public_key()).await;
    let (_, done) = open(&c, &runtime).await.unwrap();
    assert_eq!(done["party"], b64url_encode(&AGENT.0));

    // C15
    let action = sample_plan().sample.unwrap().action_ref();
    let content = GrantContent {
        basis: GrantBasis::Anchor(kmeta::meta_anchor(&c.domain)),
        holder: SubjectSelector::Pred(BTreeSet::from([Conjunct {
            claim_class: Class::OperatedBy.name(),
            value: Some(EqValue::Bytes(c.root.0.to_vec())),
        }])),
        authority: authority(BTreeSet::from([action.clone()]), "work", BTreeSet::new()),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    };
    let (exercise, _) = root_commit(&c.w, c.domain, AGENT, Payload::GrantIssue(content)).await;
    let held = HoldingRef {
        grant: kmeta::object_id(&exercise, kind::GRANT, 0),
        holder: AGENT,
        since: episode(&c).await,
    };

    let Browser { key, .. } = runtime;
    let runtime = Runtime(key);
    let adp = Recorded::new(&c.w);
    let exercise = |path: &str| {
        Exercise::new(
            c.domain,
            AGENT_PEP,
            AgentPlan {
                intent: intent(&action, path),
                basis: Some(ExerciseBasis::Holding(held)),
                capacity: Some(Capacity::Own),
            },
            nonce(),
        )
        .unwrap()
    };
    let step = exercise("w-1").ask(&adp, &runtime, &Wall).unwrap();
    assert!(matches!(step, Step::Proceed(_)), "{step:?}");
    let stranger = Runtime(SoftSigner::generate_p256().unwrap().0);
    let step = exercise("w-2").ask(&adp, &stranger, &Wall).unwrap();
    assert!(!matches!(step, Step::Proceed(_)), "{step:?}");

    // INV-23
    let agent_id = b64url_encode(&AGENT.0);
    let retired = c
        .rest_write(
            &Method::POST,
            &format!("/admin/v1/realms/acme/agents/{agent_id}/retire"),
            ("retireAgent", Some(&agent_id)),
            serde_json::json!({}),
            None,
        )
        .await;
    assert!(retired.status.is_success(), "{}", retired.body);
    let courier = super::super::recovery::courier(&c);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut n = 0;
    loop {
        n += 1;
        let step = exercise(&format!("w-after-{n}"))
            .ask(&adp, &runtime, &Wall)
            .unwrap();
        if !matches!(step, Step::Proceed(_)) {
            break;
        }
        let r = courier.step().await.unwrap();
        assert!(std::time::Instant::now() < deadline, "{r:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // PI-13
    adp.only_standard();
}
