//! Cloud agent (§11.19): a hosted agent's own Party, registered by its operator, with one
//! Instance for its session; P's Grant for P; a `REQUIRE_ACTION` it cannot meet itself; P's
//! invitation through Relay (`relay.message.approval_requested.v1`, the stand-in for CIBA until
//! Stage 10, OP-154 m.3 (ff)); P's Approval Act Statement on the hosted Approval Surface; the
//! agent's `commit` again on the same nonce; then revocation by a new decision and the
//! session's end as `instance_terminate`.

use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::notify::message::{Address, Body as Said, Message, Prompt};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::ports::Notifier as _;
use access_internal_api::instances::{terminate_intent, terminate_payload};
use access_kernel::meta::kind;
use access_sdk::agent::contract::{Proof, Step};
use access_sdk::agent::decision::{Route, TermKind};

use super::*;

/// P's invitation to the waiting approval, through the identity plane's Relay outbox: a link
/// to P's own account and the requester's name, never the authority it asks for (§11.14.2).
async fn invite(d: &Desk) {
    let route = route_by_slug(&d.w.db.router, "acme")
        .await
        .unwrap()
        .unwrap();
    let keks = crate::login::RealmKeks::new(Arc::clone(&d.w.keys));
    let kek = keks.vault(route.realm).unwrap().kek;
    let ids = crate::ids::CellIds::new(d.w.keys.clone()).key().unwrap();
    let realm = access_identity_account::app::Realm {
        tenant: route.tenant,
        realm: route.realm,
        kek: &*kek,
        ids: &ids,
    };
    let mut t = TenantTx::begin(&d.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock)
        .notify(
            &mut t,
            &Message {
                subject: d.subject,
                to: Address::Email(String::from("test.user@acme.example")),
                locale: None,
                valid_since_ms: Some(1),
                body: Said::Prompt {
                    prompt: Prompt::ApprovalRequested,
                    link: Secret::new(format!("{}/account", d.user.issuer)),
                    name: String::from("Mail agent"),
                    expires_at_ms: now_ms() + 600_000,
                },
            },
        )
        .await
        .unwrap();
    t.commit().await.unwrap();
}

// §11.19, §11.14.2, §9.14.1, §9.14.5, E49, EI-18, AGI-8, A-1, A-2, A-4, INV-4, INV-19, PI-13, EI-6,
// OP-154 m.3 (ff), Ek B 4452, 4457
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cloud_agent_waits_for_its_principals_approval_and_commits_on_the_same_nonce() {
    let d = Desk::open("walk-cloud", false).await;
    assert_eq!(
        d.w.plane.instances(d.domain, AGENT).await.unwrap(),
        vec![d.instance]
    );
    // INV-4
    let (parent, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);

    // §9.14.1
    let step = d.ask(&mut ex);
    let Step::Wait(wait) = &step else {
        panic!("{step:?}");
    };
    let approval = wait
        .unmet
        .iter()
        .find(|u| u.kind == TermKind::Contribution)
        .unwrap_or_else(|| panic!("{wait:?}"));
    assert_eq!(approval.class.as_data(), "approve");
    // E49, OP-154 m.13 (a)
    assert_eq!(approval.floors.get("surface"), Some(&2), "{wait:?}");
    assert_eq!(
        approval.floors.get("phishing_resistant"),
        Some(&1),
        "{wait:?}"
    );
    assert_eq!(wait.routes, [Route::Coordinator], "{wait:?}");
    // §11.14.2, OP-154 m.3 (ff)
    invite(&d).await;
    let invites = identity_events_until(
        &d.w.db,
        Prompt::ApprovalRequested.kind(),
        |q| !q.is_empty(),
        "the invitation",
    )
    .await;
    assert_eq!(invites.len(), 1);
    let sealed = &invites[0].payload;
    assert!(
        !sealed.windows(ex.nonce().len()).any(|w| w == ex.nonce()),
        "the invitation carries no authority"
    );
    // A-4, EI-18
    let before = intent_digest(&access_local_client::intent::parse(&intent).unwrap()).unwrap();
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let contribution = d.approve(&ex, &intent).await;
    ex.prove(Proof::Contribution(contribution)).unwrap();
    let step = d.ask(&mut ex);
    let Step::Proceed(allowed) = &step else {
        panic!("{step:?}");
    };
    // A-2, INV-19
    assert_eq!(*allowed.intent(), before);
    assert_eq!(Some(*allowed.exercise()), ex.exercise_ref());
    let other = access_local_client::intent::parse(&d.intent_json("other").await).unwrap();
    assert!(!allowed.covers(&other));

    // EI-6
    super::root_revoke(&d.w, d.domain, parent.grant, d.person).await;
    let mut after = d.exercise(&d.intent_json("main").await, held);
    let step = d.ask(&mut after);
    assert!(matches!(step, Step::Stop(_)), "{step:?}");

    // §11.21.1
    let validity = Window {
        from: now_ms() - 60_000,
        until: now_ms() + 600_000,
    };
    let end = terminate_intent(d.instance, validity).unwrap();
    let n = nonce();
    let basis = ExerciseBasis::Anchor(meta::object_id(
        &d.domain,
        kind::ANCHOR,
        access_authority_core::genesis::IDP_ANCHOR,
    ));
    let ais = super::super::agent::ais_by(
        &d.runtime.0,
        &Statement {
            domain: d.domain,
            nonce: n.clone(),
            intent: intent_digest(&end).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now_ms(),
            exercise: None,
        },
    )
    .unwrap();
    let v =
        d.w.plane
            .decide(access_internal_api::idp::Submission {
                domain: d.domain,
                nonce: n,
                intent: end,
                payload: Some(Box::new(terminate_payload(d.instance))),
                basis,
                capacity: Capacity::Own,
                ais,
                contributions: Vec::new(),
                pep: String::from(IDENTITY_PEP),
                actor: Some(AGENT),
            })
            .await
            .unwrap();
    assert!(
        matches!(v, access_internal_api::idp::Verdict::Committed(_)),
        "{v:?}"
    );
    assert_eq!(
        d.w.plane.instances(d.domain, AGENT).await.unwrap(),
        Vec::<Id>::new()
    );
    let (_, again) = d.agent_grant().await;
    let mut ended = d.exercise(&d.intent_json("main").await, again);
    let step = d.ask(&mut ended);
    assert!(
        !matches!(step, Step::Proceed(_) | Step::Wait(_)),
        "{step:?}"
    );

    // PI-13
    d.adp.only_standard();
    d.close().await;
}
