//! The Work Gate on the real server (§7.9.5.3, §8.17.6.1, E7, E41, EI-4, G30, OP-156 m.3 (t)):
//! a coordinator places a Gate on an intent that needs one `approve` contribution; the person
//! approves once on the hosted Approval Surface and the act yields two records, Access's
//! contribution and the coordinator's Declaration citing its `ExerciseID`. Whatever the
//! coordinator says about its Gate, it never satisfies the requirement and never lifts a DENY.

use access_kernel::aas::ApprovalAct;
use access_sdk::agent::contract::{Proof, Step};
use access_store::authority::read_head;
use access_store::scope::DomainId;

use super::*;

/// The coordinator's own record of a Gate (Work's, never Access's): what it declared and the
/// contribution it cites.
#[derive(Debug, Default)]
struct Gate {
    declared: Option<Digest>,
    cites: Option<Digest>,
    declined: bool,
}

fn random_digest() -> Digest {
    Digest(access_crypto::random::bytes::<32>().unwrap())
}

impl Desk {
    async fn head(&self) -> u64 {
        read_head(&self.w.db.sequencer, &DomainId::from_bytes(self.domain.0))
            .await
            .unwrap()
            .pos
    }

    /// P approves `ex` on the hosted surface, the push naming the coordinator's Gate: the
    /// contribution's `ExerciseID` and the statement the surface kept.
    async fn approve_gate(
        &self,
        ex: &Exercise,
        intent: &serde_json::Value,
        gate: (Digest, Digest),
    ) -> (Digest, ApprovalAct) {
        use access_local_client::approve::{Approve, approve};
        use access_local_client::passkey::{Passkey, relying_party};
        let envelope = access_local_client::intent::parse(intent).unwrap();
        let digest = intent_digest(&envelope).unwrap();
        let now = server_time(&self.w.db.app).await.unwrap();
        let request = serde_json::json!({
            "requester": {
                "party": b64url_encode(&AGENT.0),
                "instance": b64url_encode(&self.instance.0),
            },
            "action": intent["action"],
            "resource": intent["resources"][0],
            "params": intent["params"],
            "capacity": { "for": b64url_encode(&self.person.0) },
            "reason": "Gate: close the main ledger for this period.",
            "require_action": {
                "domain": b64url_encode(&self.domain.0),
                "nonce": b64url_encode(ex.nonce()),
                "intent": b64url_encode(&digest.0),
            },
            "expires_at": now + 3_600_000,
        });
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        let done = approve(
            &self.http,
            &Approve {
                issuer: &self.user.issuer,
                api_base: "https://access.test",
                redirect_uri: &self.user.redirect_uri,
                identifier: &self.user.identifier,
                passkey: &passkey,
                device: &device,
                pep_leaf_der: &self.leaf,
                domain: self.domain,
                party: self.person,
                instance: Some(id_of(&self.user.instance)),
                intent,
                basis: holding_of(&self.allowed["basis"]),
                contribution: holding_of(&self.allowed["contribution"]["basis"]),
                reason: "Gate: close the main ledger for this period.",
                request: Some(&request),
                work_gate: Some(gate),
            },
        )
        .await
        .unwrap();
        assert_eq!(done["render_digest_verified"], true, "{done}");
        let contribution = Digest(
            <[u8; 32]>::try_from(access_kernel::json::b64url_decode(done["contribution"].as_str().unwrap()).unwrap())
                .unwrap(),
        );
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let row = access_store::approvals::approval_by_uri(&mut t, done["request_uri"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        t.commit().await.unwrap();
        assert_eq!(row.exercise, Some(contribution.0));
        let aas = suiss_crypto::dcbor::decode(&row.aas.unwrap(), suiss_crypto::dcbor::Limits::CEILING)
            .unwrap();
        (contribution, ApprovalAct::from_value(&aas).unwrap())
    }
}

// §8.17.6.1, X7, E7, EI-4, G30, F8, §9.14, §9.14.1, P29, PI-14, OP-156 m.3 (t),
// Ek B 5183, 5192, 5253, 5257, 5259, 5378
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gate_approval_is_one_ceremony_two_records_and_never_an_allow() {
    let d = Desk::open("q16-work-gate", false).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    let step = d.ask(&mut ex);
    assert!(matches!(step, Step::Wait(_)), "{step:?}");

    // G30, EI-4
    let gate = (random_digest(), random_digest());
    let mut work = Gate {
        declared: Some(gate.1),
        ..Gate::default()
    };
    let before = d.head().await;
    ex.prove(Proof::Contribution(gate.1)).unwrap();
    let step = d.ask(&mut ex);
    assert!(!matches!(step, Step::Proceed(_)), "{step:?}");
    let mut uncovered = intent.clone();
    uncovered["action"]["name"] = serde_json::json!("reopen");
    let mut denied = d.exercise(&uncovered, held);
    let step = d.ask(&mut denied);
    assert!(matches!(step, Step::Stop(_)), "{step:?}");
    assert!(denied.prove(Proof::Contribution(gate.1)).is_err());

    // X7
    let mut fresh = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut fresh), Step::Wait(_)));
    let (contribution, aas) = d.approve_gate(&fresh, &intent, gate).await;
    assert_eq!(aas.work_gate, Some(gate));
    assert_eq!(aas.nonce.len(), 16);
    work.cites = Some(contribution);
    assert!(d.head().await > before);

    // §8.17.6.1
    fresh.prove(Proof::Contribution(contribution)).unwrap();
    let Step::Proceed(allowed) = d.ask(&mut fresh) else {
        panic!("the contribution alone satisfies the requirement");
    };
    assert!(allowed.covers(&access_local_client::intent::parse(&intent).unwrap()));
    assert_eq!(work.cites, Some(contribution));
    assert!(work.declared.is_some());

    // F8, E7
    let mut other_step = intent.clone();
    other_step["context"] = serde_json::json!({ "step": b64url_encode(&random_digest().0) });
    let mut moved = d.exercise(&other_step, held);
    assert!(matches!(d.ask(&mut moved), Step::Wait(_)));
    moved.prove(Proof::Contribution(contribution)).unwrap();
    let step = d.ask(&mut moved);
    assert!(!matches!(step, Step::Proceed(_)), "{step:?}");

    // X7: a decline is the coordinator's Declaration alone
    let mut declined = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut declined), Step::Wait(_)));
    let at = d.head().await;
    work.declined = true;
    assert_eq!(d.head().await, at);
    let step = d.ask(&mut declined);
    assert!(matches!(step, Step::Wait(_)), "{step:?}");
    assert!(work.declined);

    // PI-13
    d.adp.only_standard();
    d.close().await;
}
