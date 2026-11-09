//! Local agent (§11.19): an agent P operates on P's own device, its Instance opened under P's
//! own session there; the decision is asked of the ADP directly; the approval is P's Approval
//! Act Statement with the platform authenticator on the same device; the decision holds for
//! its envelope until its horizon, and after a reconnect the next decision learns a revoked
//! Grant.

use access_sdk::agent::contract::{Proof, Step};

use super::*;

// §11.19, §8.18.3, A-2, A-4, EI-18, AGI-8, PI-13, OP-154 m.3 (ff), Ek B 4453, 4457
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_agent_is_approved_on_the_same_device_and_asks_again_on_reconnect() {
    let d = Desk::open("walk-local", true).await;
    assert_eq!(
        d.w.plane.instances(d.domain, AGENT).await.unwrap(),
        vec![d.instance]
    );
    let (parent, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    let step = d.ask(&mut ex);
    assert!(matches!(step, Step::Wait(_)), "{step:?}");
    // AGI-8
    let contribution = d.approve(&ex, &intent).await;
    ex.prove(Proof::Contribution(contribution)).unwrap();
    let step = d.ask(&mut ex);
    let Step::Proceed(allowed) = &step else {
        panic!("{step:?}");
    };

    // A-2
    let envelope = access_local_client::intent::parse(&intent).unwrap();
    assert!(allowed.covers(&envelope));
    assert!(envelope.validity.until <= now_ms() + 600_000);

    // EI-6
    super::root_revoke(&d.w, d.domain, parent.grant, d.person).await;
    let mut fresh = d.exercise(&d.intent_json("main").await, held);
    let step = d.ask(&mut fresh);
    assert!(matches!(step, Step::Stop(_)), "{step:?}");

    // PI-13
    d.adp.only_standard();
    d.close().await;
}
