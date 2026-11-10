//! Cloud agent (§11.19): a hosted agent's own Party, registered by its operator, with one
//! Instance for its session; P's Grant for P; a `REQUIRE_ACTION` it cannot meet itself; the
//! agent's CIBA backchannel request naming it (OP-155 m.3 (l), OP-154 m.17 (b)), P's Relay
//! `CibaInvite`, P's Approval Act Statement on the hosted Approval Surface, the contribution the
//! agent learns by polling; the agent's `commit` again on the same nonce; then revocation by a new
//! decision and the session's end as `instance_terminate`.

use access_internal_api::instances::{terminate_intent, terminate_payload};
use access_kernel::meta::kind;
use access_sdk::agent::contract::{Proof, Step};
use access_sdk::agent::decision::{Route, TermKind};

use super::ciba::contribution_of;
use super::*;

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
    // §11.14.2, §9.9.5, OP-155 m.3 (l), OP-154 m.17 (b), Ek B 4365, 4718, 4719
    let client = d.ciba_client("Mail agent", false).await;
    d.ciba_on(false, &[]).await;
    let hint = d.hint_token(&client).await;
    let (status, asked) = d
        .bc_authorize(
            &client,
            &d.ciba_params(&ex, &intent, ("login_hint_token", &hint), Some("Code 4F2Q")),
        )
        .await;
    assert_eq!(status, 200, "{asked}");
    let auth_req_id = String::from(asked["auth_req_id"].as_str().unwrap());
    assert_eq!(asked["interval"], 5);
    let invites = identity_events_until(
        &d.w.db,
        "relay.message.ciba_invite.v1",
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
    // P54
    let (status, body) = d.ciba_poll(&client, &auth_req_id).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("authorization_pending"))
    );
    let (status, body) = d.ciba_poll(&client, &auth_req_id).await;
    assert_eq!((status, body["error"].as_str()), (400, Some("slow_down")));
    // A-4, EI-18
    let before = intent_digest(&access_local_client::intent::parse(&intent).unwrap()).unwrap();
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let request = d.ciba_request(&auth_req_id).await;
    let mut jar = d.person().await;
    let (status, preview) = d.ciba_preview(&mut jar, &request).await;
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["client"], "Mail agent");
    assert_eq!(preview["binding_message"], "Code 4F2Q");
    assert!(preview["contribution_basis"].is_object(), "{preview}");
    assert_eq!(
        holding_of(&preview["contribution_basis"]),
        holding_of(&d.allowed["contribution"]["basis"]),
        "{preview}"
    );
    let done = d.ciba_aas(&preview["request"], &intent).await;
    let (status, body) = d
        .ciba_answer(
            &jar,
            &request,
            preview["csrf"].as_str().unwrap(),
            done["request_uri"].as_str(),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let (status, token) = d.ciba_poll(&client, &auth_req_id).await;
    assert_eq!(status, 200, "{token}");
    assert_eq!(token["token_type"], "DPoP");
    assert!(token.get("id_token").is_some() && token.get("authorization_details").is_none());
    // PI-3, §9.14.5 k.2
    let contribution = contribution_of(&token);
    assert_eq!(
        b64url_encode(&contribution.0),
        done["contribution"].as_str().unwrap()
    );
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
