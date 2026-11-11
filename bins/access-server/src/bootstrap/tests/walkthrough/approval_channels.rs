//! The approval channels on the real server (OP-157 m.3 (m), §13.7.3, SEC26, TN-100,
//! §8.17.6.3, §8.17.11.4, X-L7): a CT1 request goes to the registered approver device with its
//! whole render and is approved there with the device key over H(AAS); other tiers get only an
//! invitation; one invitation per approver and intent, five an hour from a requester, then 429; a
//! batch is at most ten requests of one requester and one action, each with its own statement and
//! contribution, and a domain's `approval_surfaces` decide which statements count.

use access_identity_admin::domain::Change;
use access_kernel::aas::ApprovalAct;
use access_kernel::combinator::Capacity;
use access_kernel::model::{Binding, Consumption, Independence, ProofKind, RequirementTerm};
use access_kernel::render;
use access_local_client::approve::{Approve, push_only};
use access_local_client::login::{Jar, post_json};
use access_local_client::passkey::{Passkey, relying_party};
use access_sdk::agent::contract::{Proof, Step};
use access_sdk::approver::inline::{
    InlineRequest, StatementFacts, answer_body, approve_to_be_signed, deny_to_be_signed, statement,
};
use access_sdk::approver::{registration_body, registration_message, thumbprint, to_raw_signature};
use serde_json::Value;
use suiss_crypto::cose::PublicKey as CosePublicKey;
use suiss_crypto::signer::SoftSigner;

use super::*;

/// A device signing `approval-inline` answers: the approver key, activated in the store.
struct Phone {
    key: SoftSigner,
    print: [u8; 32],
}

impl Desk {
    /// P registers an approver with the public SDK; the store records it attested with an app
    /// PIN, as `/v1/approvers/{device}/activate` does.
    async fn phone(&self) -> Phone {
        let issuer = self.user.issuer.clone();
        let (key, _) = SoftSigner::generate_p256().unwrap();
        let CosePublicKey::P256(public) = key.public_key() else {
            panic!("p-256")
        };
        let print = thumbprint(&public).unwrap();
        let mut jar = self.person().await;
        let proof =
            to_raw_signature(&key.sign(&registration_message(&issuer, &print)).unwrap()).unwrap();
        let body: Value =
            serde_json::from_str(&registration_body("P's phone", &public, &proof)).unwrap();
        let made = post_json(
            &self.http,
            &format!("{issuer}/v1/approvers"),
            &mut jar,
            Some(body),
        )
        .await
        .unwrap();
        assert_eq!(made.status, 201, "{}", made.json());
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let row = t.device_key_by_thumbprint(&print).await.unwrap().unwrap();
        assert!(t.attest_app_factor_key(self.subject, row.id).await.unwrap());
        t.commit().await.unwrap();
        Phone { key, print }
    }

    /// The coordinator's push of the waiting `ex`, as `adjust` changes it: the push's status,
    /// body and the contribution envelope it carried.
    async fn push_waiting(
        &self,
        ex: &Exercise,
        intent: &Value,
        adjust: impl FnOnce(&mut Value),
    ) -> (u16, Value, Value) {
        let request = self.pushed_request(ex, intent).await;
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        push_only(
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
                reason: "The mail agent wants to close the main ledger for you.",
                request: Some(&request),
                work_gate: None,
            },
            adjust,
        )
        .await
        .unwrap()
    }

    /// The root tightens the domain's `approval_surfaces` policy default (CT1, OP-157 m.3 (n)).
    async fn set_policy_default_surfaces(&self, names: &[&str]) {
        root_commit(
            &self.w,
            self.domain,
            self.person,
            Payload::PolicySet {
                policy: None,
                content: access_authority_core::restrict::patterns::support_protected().unwrap(),
                defaults: Some(meta::PolicyDefaults {
                    approval_surfaces: Some(names.iter().map(|n| (*n).to_string()).collect()),
                    ..meta::PolicyDefaults::default()
                }),
            },
        )
        .await;
    }

    /// The outbox's `approval_inline` messages; their bodies are sealed under the recipient's
    /// key, so the test holds the render the same Kernel produces.
    async fn inline_sent(&self) -> usize {
        identity_events_until(
            &self.w.db,
            "relay.message.approval_inline.v1",
            |q| !q.is_empty(),
            "the inline approval",
        )
        .await
        .len()
    }

    /// The statement the approver device signs for `request`.
    async fn inline_statement(
        &self,
        request: &InlineRequest,
        env: &Value,
        shown: &render::Render,
    ) -> ApprovalAct {
        let now = server_time(&self.w.db.app).await.unwrap();
        statement(
            request,
            shown,
            StatementFacts {
                class: String::from("approve"),
                instance: id_of(&self.user.instance),
                party: self.person,
                capacity: Capacity::Own,
                domain: self.domain,
                nonce: access_kernel::json::b64url_decode(env["nonce"].as_str().unwrap()).unwrap(),
                issued_at: now,
                expires_at: now + 600_000,
            },
        )
    }
}

/// `approval_inline` as the approver device receives it for `intent`, in the Kernel's own
/// render.
fn inline_request(intent: &Value) -> (InlineRequest, render::Render) {
    let envelope = access_local_client::intent::parse(intent).unwrap();
    let shown = render::of(None, &envelope, render::DEFAULT_LOCALE).unwrap();
    let bytes = render::encode(&shown).unwrap();
    let digest = render::digest(&shown).unwrap();
    (
        InlineRequest {
            intent: intent_digest(&envelope).unwrap(),
            render: bytes,
            render_digest: digest,
            expires_at_ms: u64::MAX,
        },
        shown,
    )
}

// SEC26, TN-100, §13.7.3, §8.17.6.3, OP-157 m.3 (m), X-L7, Ek B 5416, 5477, 5499, 5631
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ct1_approval_inside_the_notification_is_signed_on_the_approver_device() {
    let d = Desk::open("v7-inline", false).await;
    let phone = d.phone().await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));

    // §13.7.3: closed until the realm opens it
    d.root_change(Change::ApprovalInline(true)).await;
    let (status, pushed, env) = d.push_waiting(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{pushed}");
    assert_eq!(d.inline_sent().await, 1, "a separate template, X-L7");
    let (request, shown) = inline_request(&intent);
    assert_eq!(request.verified().unwrap(), shown);

    let act = d.inline_statement(&request, &env, &shown).await;
    let signed = approve_to_be_signed(&request, &act, &phone.print);
    let signature = to_raw_signature(&phone.key.sign(&signed).unwrap()).unwrap();
    let mut browser = Jar::default();
    let answered = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&answer_body(&signed, &signature)).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(answered.status, 200, "{}", answered.json());
    let exercise = Digest(
        <[u8; 32]>::try_from(
            access_kernel::json::b64url_decode(answered.json()["exercise"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
    );
    ex.prove(Proof::Contribution(exercise)).unwrap();
    assert!(matches!(d.ask(&mut ex), Step::Proceed(_)));

    // The invitation is single use.
    let again = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&answer_body(&signed, &signature)).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(again.status, 404, "{}", again.json());

    // C30: a refusal uses the invitation up
    let refused = d.intent_json("second").await;
    let mut other = d.exercise(&refused, held);
    assert!(matches!(d.ask(&mut other), Step::Wait(_)));
    let (status, pushed, env) = d.push_waiting(&other, &refused, |_| {}).await;
    assert_eq!(status, 201, "{pushed}");
    let (request, shown) = inline_request(&refused);
    let deny = deny_to_be_signed(&request, &phone.print);
    let signature = to_raw_signature(&phone.key.sign(&deny).unwrap()).unwrap();
    let denied = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&answer_body(&deny, &signature)).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(denied.status, 200, "{}", denied.json());
    assert_eq!(denied.json()["decision"], "denied");
    let act = d.inline_statement(&request, &env, &shown).await;
    let late = approve_to_be_signed(&request, &act, &phone.print);
    let signature = to_raw_signature(&phone.key.sign(&late).unwrap()).unwrap();
    let after = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&answer_body(&late, &signature)).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(after.status, 404, "{}", after.json());
    d.close().await;
}

// §13.7.3, SEC26, TN-100, OP-157 m.3 (m), Ek B 5477, 5499
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_realm_that_did_not_open_the_channel_answers_approval_inline_off() {
    let d = Desk::open("v7-inline-off", false).await;
    let phone = d.phone().await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let (status, pushed, env) = d.push_waiting(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{pushed}");
    let (request, shown) = inline_request(&intent);
    let act = d.inline_statement(&request, &env, &shown).await;
    let signed = approve_to_be_signed(&request, &act, &phone.print);
    let signature = to_raw_signature(&phone.key.sign(&signed).unwrap()).unwrap();
    let mut browser = Jar::default();
    let answered = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&answer_body(&signed, &signature)).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(answered.status, 403, "{}", answered.json());
    assert_eq!(answered.json()["code"], "approval-inline-off");
    d.close().await;
}

// §8.17.11.4, A-3, C30, OP-157 m.3 (m), Ek B 5620, 5633
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sixth_invitation_in_an_hour_is_429_and_one_intent_invites_once() {
    let d = Desk::open("v7-invites", false).await;
    let (_, held) = d.agent_grant().await;
    let route = route_by_slug(&d.w.db.router, "acme")
        .await
        .unwrap()
        .unwrap();
    let invites = || async {
        let mut t = TenantTx::begin(&d.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let (n, _) = access_store::approvals::invites_since(&mut t, &AGENT.0, &d.subject, 0)
            .await
            .unwrap();
        t.commit().await.unwrap();
        n
    };
    let mut held_exercises = Vec::new();
    for n in 0..6 {
        let ledger = format!("l{n}");
        let intent = d.intent_json(&ledger).await;
        let mut ex = d.exercise(&intent, held);
        assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
        let (status, pushed, _) = d.push_waiting(&ex, &intent, |_| {}).await;
        if n < 5 {
            assert_eq!(status, 201, "{pushed}");
            assert_eq!(invites().await, n + 1);
            // A-3
            let (again, again_body, _) = d.push_waiting(&ex, &intent, |_| {}).await;
            assert_eq!(again, 201, "{again_body}");
            assert_eq!(invites().await, n + 1, "the same intent invites once");
        } else {
            assert_eq!(status, 429, "{pushed}");
            assert_eq!(pushed["code"], "approval-invite-limit");
            assert_eq!(invites().await, 5);
        }
        held_exercises.push(ex);
    }
    d.close().await;
}

// §13.7.3, OP-157 m.3 (m), (n), Ek B 5475
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_statement_from_a_surface_the_domain_does_not_accept_is_refused() {
    let d = Desk::open("v7-surfaces", false).await;
    let phone = d.phone().await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    d.root_change(Change::ApprovalInline(true)).await;
    let (status, pushed, env) = d.push_waiting(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{pushed}");
    let (request, shown) = inline_request(&intent);
    // OP-157 m.3 (n)
    d.set_policy_default_surfaces(&["suiss-approval-surface"])
        .await;
    let act = d.inline_statement(&request, &env, &shown).await;
    let signed = approve_to_be_signed(&request, &act, &phone.print);
    let signature = to_raw_signature(&phone.key.sign(&signed).unwrap()).unwrap();
    let mut browser = Jar::default();
    let answered = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&answer_body(&signed, &signature)).unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(answered.status, 409, "{}", answered.json());
    assert_eq!(answered.json()["reason"], "approval-surface-not-accepted");
    d.close().await;
}

fn surface_term() -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from("approve"),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctSurface,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    }
}

// §13.7.3, §13.2, OP-157 m.3 (m), m.14 (o), Ek B 5476, 5498
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hosted_surface_contribution_never_meets_a_distinct_surface_term() {
    let d = Desk::open("v7-distinct", false).await;
    let held = d.agent_grant_needing(surface_term()).await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let approved = d.approve(&ex, &intent).await;
    ex.prove(Proof::Contribution(approved)).unwrap();
    assert!(
        !matches!(d.ask(&mut ex), Step::Proceed(_)),
        "a statement from the hosted page alone meets no distinct-surface term (m.14 (o))"
    );
    d.close().await;
}

/// Starts a batch of the given pushed `request_uri`s in the person's browser.
async fn start_batch(d: &Desk, jar: &mut Jar, requests: &[String]) -> (u16, Value) {
    let started = post_json(
        &d.http,
        &format!("{}/v1/approve/batch", d.user.issuer),
        jar,
        Some(serde_json::json!({
            "requests": requests,
            "redirect_uri": d.user.redirect_uri,
            "state": "batch",
        })),
    )
    .await
    .unwrap();
    (started.status, started.json())
}

// §13.7.3, §8.17.6.3, SEC26, OP-157 m.3 (m), Ek B 5478, 5632
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_is_ten_at_most_of_one_requester_each_with_its_own_statement() {
    use access_local_client::login::attach_device;
    let d = Desk::open("v7-batch", false).await;
    let (_, held) = d.agent_grant().await;
    let mut exercises = Vec::new();
    let mut uris = Vec::new();
    for ledger in ["a", "b"] {
        let intent = d.intent_json(ledger).await;
        let mut ex = d.exercise(&intent, held);
        assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
        let (status, pushed, _) = d.push_waiting(&ex, &intent, |_| {}).await;
        assert_eq!(status, 201, "{pushed}");
        uris.push(String::from(pushed["request_uri"].as_str().unwrap()));
        exercises.push(ex);
    }
    let mut jar = d.person().await;
    let device = d.token.signer(local::TEST_DEVICE_LABEL).unwrap();
    attach_device(&d.http, &d.user.issuer, &mut jar, &device)
        .await
        .unwrap();

    // §13.7.3: closed until the realm opens it
    let (status, body) = start_batch(&d, &mut jar, &uris).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("approval-batch-invalid")),
        "{body}"
    );
    d.root_change(Change::ApprovalBatch(true)).await;

    // §13.7.3: the eleventh item
    let eleven = vec![uris[0].clone(); 11];
    let (status, body) = start_batch(&d, &mut jar, &eleven).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("approval-batch-invalid")),
        "{body}"
    );

    let (status, started) = start_batch(&d, &mut jar, &uris).await;
    assert_eq!(status, 201, "{started}");
    // §8.17.6.3
    assert_eq!(started["title"], "Approve these 2 requests");
    let items = started["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_ne!(
        items[0]["options"]["challenge"],
        items[1]["options"]["challenge"]
    );
    assert!(
        items
            .iter()
            .all(|i| !i["render"]["fields"].as_array().unwrap().is_empty())
    );

    let passkey_key = d.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
    let (rp_id, origin) = relying_party(&d.user.issuer).unwrap();
    let passkey = Passkey {
        key: &passkey_key,
        rp_id: &rp_id,
        origin: &origin,
    };
    let answers: Vec<Value> = items
        .iter()
        .map(|i| {
            let challenge = access_kernel::json::b64url_decode(i["options"]["challenge"].as_str().unwrap()).unwrap();
            serde_json::json!({ "flow": i["flow"], "credential": passkey.assert(&challenge).unwrap() })
        })
        .collect();
    let finished = post_json(
        &d.http,
        &format!("{}/v1/approve/batch/{}", d.user.issuer, started["flow"].as_str().unwrap()),
        &mut jar,
        Some(serde_json::json!({ "items": answers, "redirect_uri": d.user.redirect_uri, "state": "batch" })),
    )
    .await
    .unwrap();
    assert_eq!(finished.status, 200, "{}", finished.json());
    let results = finished.json();
    let results = results["items"].as_array().unwrap().clone();
    assert_eq!(results.len(), 2);
    let digest = |v: &Value| {
        Digest(
            <[u8; 32]>::try_from(access_kernel::json::b64url_decode(v.as_str().unwrap()).unwrap())
                .unwrap(),
        )
    };
    assert_ne!(
        digest(&results[0]["exercise"]),
        digest(&results[1]["exercise"])
    );
    for (mut ex, result) in exercises.into_iter().zip(&results) {
        ex.prove(Proof::Contribution(digest(&result["exercise"])))
            .unwrap();
        assert!(matches!(d.ask(&mut ex), Step::Proceed(_)));
    }
    d.close().await;
}
