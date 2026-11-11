//! The Approval Surface's WYSIWYS page on the real server (§8.17.6, §9.14.5, E32, PI-17, U7,
//! OP-157 m.3 (l)): what the approver sees is the decision point's render bound to the
//! statement, with the capacity, what is still needed in checkable words, what approving does
//! and doesn't do and the concrete act; a render that can't be shown faithfully, a body that
//! doesn't match and a viewer outside the eligible set get no button.

use access_kernel::aas::ApprovalAct;
use access_kernel::codec::Canonical;
use access_kernel::model::{Binding, Consumption, Independence, ProofKind, RequirementTerm};
use access_kernel::render;
use access_local_client::approve::{Approve, open_surface};
use access_local_client::passkey::{Passkey, relying_party};
use access_sdk::agent::contract::{Proof, Step};
use serde_json::{Value, json};

use super::*;

const REASON: &str = "The mail agent wants to close the main ledger for you.";

impl Desk {
    /// P's Grant of the allowed action to the agent, for P, whose approval term is `term`
    /// instead of the sample's.
    async fn agent_grant_needing(&self, term: RequirementTerm) -> HoldingRef {
        let mut to_person = approve_plan(None)
            .sample
            .unwrap()
            .allowed_grant(&self.domain, self.person)
            .unwrap();
        to_person.authority.requirements = BTreeSet::from([term]);
        to_person.authority.delegation = DelegationTerms {
            depth: 1,
            downstream_holder_class: Some(SubjectSelector::Party(AGENT)),
        };
        let mut onward = to_person.authority.clone();
        onward.delegation.depth = 0;
        let parent = root_grant(&self.w, self.domain, to_person).await;
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        issue(
            &self.w,
            self.domain,
            &device,
            Some(parent),
            AGENT,
            onward,
            (BTreeSet::from([Capacity::For(self.person)]), Capacity::Own),
        )
        .await
    }

    /// The agent's waiting request for `ex` as a coordinator pushes it.
    async fn pushed_request(&self, ex: &Exercise, intent: &Value) -> Value {
        let envelope = access_local_client::intent::parse(intent).unwrap();
        let digest = intent_digest(&envelope).unwrap();
        let now = server_time(&self.w.db.app).await.unwrap();
        json!({
            "requester": {
                "party": b64url_encode(&AGENT.0),
                "instance": b64url_encode(&self.instance.0),
            },
            "action": intent["action"],
            "resource": intent["resources"][0],
            "params": intent["params"],
            "capacity": { "for": b64url_encode(&self.person.0) },
            "reason": REASON,
            "require_action": {
                "domain": b64url_encode(&self.domain.0),
                "nonce": b64url_encode(ex.nonce()),
                "intent": b64url_encode(&digest.0),
            },
            "expires_at": now + 3_600_000,
        })
    }

    /// P opens the surface for the agent's waiting `ex`, the push changed by `adjust`: the
    /// start answer's status and body.
    async fn surface(
        &self,
        ex: &Exercise,
        intent: &Value,
        adjust: impl FnOnce(&mut Value),
    ) -> (u16, Value) {
        let request = self.pushed_request(ex, intent).await;
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        open_surface(
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
                reason: REASON,
                request: Some(&request),
                work_gate: None,
            },
            adjust,
        )
        .await
        .unwrap()
    }

    /// The statement the surface built for the started flow `flow`.
    async fn statement(&self, flow: &str) -> ApprovalAct {
        let id = <[u8; 16]>::try_from(access_kernel::json::b64url_decode(flow).unwrap()).unwrap();
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let row = access_store::approvals::approval(&mut t, &id)
            .await
            .unwrap()
            .unwrap();
        t.commit().await.unwrap();
        let aas =
            suiss_crypto::dcbor::decode(&row.aas.unwrap(), suiss_crypto::dcbor::Limits::CEILING)
                .unwrap();
        ApprovalAct::from_value(&aas).unwrap()
    }
}

fn texts(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|l| String::from(l.as_str().unwrap()))
        .collect()
}

fn no_button(s: &Value) {
    assert!(s.get("flow").is_none(), "{s}");
    assert!(s.get("options").is_none(), "{s}");
    assert_eq!(s["render"]["approvable"], false, "{s}");
}

// U7, §9.14.5, §8.17.6.1, §8.17.6.3, E32, AP-6, X3, X7, XI-8, OP-157 m.3 (l), Ek B 5420, 5463, 5467, 5471, 5586, 5629
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_page_shows_the_bound_render_with_capacity_needs_and_effect() {
    let d = Desk::open("v6-wysiwys", false).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));

    let (status, s) = d.surface(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{s}");
    let v = &s["render"];
    let mine = render::of(
        None,
        &access_local_client::intent::parse(&intent).unwrap(),
        render::DEFAULT_LOCALE,
    )
    .unwrap();
    let shown = v["fields"].as_array().unwrap();
    assert_eq!(shown.len(), mine.fields.len());
    for (f, m) in shown.iter().zip(&mine.fields) {
        assert_eq!(f["name"], m.name.as_str());
        assert_eq!(f["text"], m.text.as_str());
        assert_eq!(f["material"], m.material);
    }
    // U7
    let act = d.statement(s["flow"].as_str().unwrap()).await;
    assert_eq!(act.render_digest, render::digest(&mine).unwrap());
    assert_eq!(act.material_fields, render::material_fields(&mine));
    assert_eq!(act.surface_profile, "suiss-approval-surface");

    assert!(
        v["capacity"]
            .as_str()
            .unwrap()
            .starts_with("You approve as: an approver for "),
        "{v}"
    );
    assert_eq!(texts(&v["still_needed"]), ["Still needed: 1 more"]);
    assert!(v.get("counts_as_one").is_none(), "{v}");
    assert_eq!(v["does"]["title"], "What this does");
    assert_eq!(v["does_not"]["title"], "What this doesn't do");
    assert!(
        texts(&v["does_not"]["lines"])
            .iter()
            .any(|l| l.contains("grants nothing else"))
    );
    assert_eq!(v["assurance_action"], "Confirm with your passkey");
    // E32
    assert_eq!(v["requester_note"], "Requester's note");
    assert_eq!(v["reason"], REASON);
    assert_eq!(v["approvable"], true);
    assert!(v.get("blocked").is_none(), "{v}");
    assert!(!s.to_string().to_lowercase().contains("independent"));

    // L14
    let changed = d.approve(&ex, &intent).await;
    ex.prove(Proof::Contribution(changed)).unwrap();
    assert!(matches!(d.ask(&mut ex), Step::Proceed(_)));
    let mut other = intent.clone();
    other["resources"][0]["path"] = json!(["led_other"]);
    let mut moved = d.exercise(&other, held);
    assert!(matches!(d.ask(&mut moved), Step::Wait(_)));
    moved.prove(Proof::Contribution(changed)).unwrap();
    assert!(!matches!(d.ask(&mut moved), Step::Proceed(_)));
    d.close().await;
}

// SA-54, §14.9, OP-157 m.3 (l), Ek B 5602
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approval_is_bound_to_the_recipient_and_the_values_it_showed() {
    let d = Desk::open("v6-linking", false).await;
    let (_, held) = d.agent_grant().await;
    let mut intent = d.intent_json("main").await;
    intent["recipient"] = json!(b64url_encode(&[0x41; 16]));
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let (status, s) = d.surface(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{s}");
    let fields = s["render"]["fields"].as_array().unwrap();
    let recipient = fields.iter().find(|f| f["name"] == "recipient").unwrap();
    assert_eq!(recipient["text"], "41".repeat(16));
    assert_eq!(recipient["material"], true);
    let approved = d.approve(&ex, &intent).await;

    let mut payee = intent.clone();
    payee["recipient"] = json!(b64url_encode(&[0x42; 16]));
    let mut value = intent.clone();
    value["params"]["ledger"] = json!({ "eq": "other" });
    for changed in [payee, value] {
        let mut other = d.exercise(&changed, held);
        assert!(matches!(d.ask(&mut other), Step::Wait(_)), "{changed}");
        other.prove(Proof::Contribution(approved)).unwrap();
        assert!(!matches!(d.ask(&mut other), Step::Proceed(_)), "{changed}");
    }
    ex.prove(Proof::Contribution(approved)).unwrap();
    assert!(matches!(d.ask(&mut ex), Step::Proceed(_)));
    d.close().await;
}

fn distinct_people(count: u64) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from("approve"),
        count,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctParty,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    }
}

// §8.17.6.4, §8.17.6.3, L13, SEC10, OP-157 m.3 (l), Ek B 5555, 5557
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_partys_two_approvals_count_as_one() {
    let d = Desk::open("v6-quorum", false).await;
    let held = d.agent_grant_needing(distinct_people(2)).await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));

    let (status, s) = d.surface(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{s}");
    assert_eq!(
        texts(&s["render"]["still_needed"]),
        ["Still needed: 2 more · not the requester · a different person"]
    );
    assert!(s["render"].get("counts_as_one").is_none());

    let first = d.approve(&ex, &intent).await;
    let (_, s) = d.surface(&ex, &intent, |_| {}).await;
    assert_eq!(
        texts(&s["render"]["still_needed"]),
        ["Still needed: 1 more · not the requester · a different person"]
    );
    assert_eq!(s["render"]["counts_as_one"], "These count as one approval");

    let second = d.approve(&ex, &intent).await;
    assert_ne!(first, second);
    let (_, s) = d.surface(&ex, &intent, |_| {}).await;
    assert_eq!(
        texts(&s["render"]["still_needed"]),
        ["Still needed: 1 more · not the requester · a different person"]
    );
    assert_eq!(s["render"]["counts_as_one"], "These count as one approval");
    assert!(!s.to_string().to_lowercase().contains("independent"));

    // L13
    ex.prove(Proof::Contribution(first)).unwrap();
    ex.prove(Proof::Contribution(second)).unwrap();
    let step = d.ask(&mut ex);
    assert!(matches!(step, Step::Wait(_)), "{step:?}");
    d.close().await;
}

// §8.17.6.1, §7.9.5.3, E26, OP-157 m.3 (l), Ek B 5630
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_outside_the_eligible_set_gets_no_button() {
    let d = Desk::open("v6-eligible", false).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));

    let (status, s) = d.surface(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{s}");
    let contribute = holding_of(&d.allowed["contribution"]["basis"]);
    root_revoke(&d.w, d.domain, contribute.grant, d.person).await;
    let (status, s) = d.surface(&ex, &intent, |_| {}).await;
    assert_eq!(status, 200, "{s}");
    no_button(&s);
    assert_eq!(
        s["render"]["blocked"],
        "You can't approve this. Who can approve it isn't shown to you."
    );
    assert_ne!(s["render"]["fields"], json!([]));
    d.close().await;
}

// E10, PI-17, §8.17.6.2, P30, XI-8, OP-157 m.3 (l), Ek B 5627, 5628
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unaccepted_schema_or_a_body_that_does_not_match_closes_the_approval() {
    let d = Desk::open("v6-faithful", false).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));

    let (status, s) = d
        .surface(&ex, &intent, |push| {
            push["request"]["action"]["schema"] = json!(b64url_encode(&[0x5c; 32]));
        })
        .await;
    assert_eq!(status, 200, "{s}");
    no_button(&s);
    assert_eq!(
        s["render"]["blocked"],
        "This request can't be displayed faithfully here; it can't be approved from this surface"
    );
    assert_eq!(s["render"]["fields"], json!([]));

    let envelope = access_local_client::intent::parse(&intent).unwrap();
    let encoded = b64url_encode(&envelope.to_bytes().unwrap());
    let (status, s) = d
        .surface(&ex, &intent, |push| {
            push["intent"] = json!(encoded);
            push["body"] = json!({ "note": b64url_encode(b"Close the ledger and pay everyone.") });
        })
        .await;
    assert_eq!(status, 200, "{s}");
    no_button(&s);
    assert_eq!(
        s["render"]["blocked"],
        "The details sent with this request don't match it. It can't be approved."
    );

    // §8.17.6.2
    let note = b"Close the main ledger for October.";
    let mut with_body = intent.clone();
    with_body["opaque"] = json!({
        "note": b64url_encode(&access_identity_ui::domain::approval::body_digest(note).0)
    });
    let mut bodied = d.exercise(&with_body, held);
    assert!(matches!(d.ask(&mut bodied), Step::Wait(_)));
    let bodied_envelope = access_local_client::intent::parse(&with_body).unwrap();
    let bodied_encoded = b64url_encode(&bodied_envelope.to_bytes().unwrap());
    let (status, s) = d
        .surface(&bodied, &with_body, |push| {
            push["intent"] = json!(bodied_encoded);
            push["body"] = json!({ "note": b64url_encode(note) });
        })
        .await;
    assert_eq!(status, 201, "{s}");
    assert_eq!(s["render"]["bodies"][0]["name"], "note");
    assert_eq!(
        s["render"]["bodies"][0]["text"],
        "Close the main ledger for October."
    );
    d.close().await;
}

// §11.4.5, §11.6, EI-18, OP-157 m.3 (l), Ek B 5426
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_is_the_approval_surface() {
    let d = Desk::open("v6-consent", false).await;
    let query = "request=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Ax&redirect_uri=https%3A%2F%2Fa.example%2Fcb&state=s1";
    let got = d
        .http
        .request(
            "GET",
            &format!("{}/consent?{query}", d.user.issuer),
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(got.status, 303, "{}", got.text());
    let location = got.header("location").unwrap();
    assert!(
        location.ends_with(&format!("/v1/approve?{query}")),
        "{location}"
    );
    assert_eq!(got.header("cache-control"), Some("no-store"));
    let posted = d
        .http
        .request(
            "POST",
            &format!("{}/consent", d.user.issuer),
            &[("origin", "https://access.test")],
            Some(("application/x-www-form-urlencoded", b"approve=yes")),
        )
        .await
        .unwrap();
    assert_eq!(posted.status, 405, "{}", posted.text());
    assert_eq!(posted.header("allow"), Some("GET"));
    d.close().await;
}
