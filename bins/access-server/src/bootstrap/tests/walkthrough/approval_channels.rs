//! The approval channels on the real server (OP-157 m.3 (m), m.17, §13.7.3, SEC26, TN-100,
//! §8.17.6.3, §8.17.11.4, X-L7): a CT1 request goes to the registered approver device with its
//! whole render and is approved there with the approver's passkey assertion over H(AAS), the
//! device key's statement alone never counting; other tiers get only an invitation; one invitation per approver and intent, five an hour from a requester, then 429; a
//! batch is at most ten requests of one requester and one action, each with its own statement and
//! contribution, and a domain's `approval_surfaces` decide which statements count.

use access_identity_admin::domain::Change;
use access_identity_webauthn::domain::software::{SoftwareAuthenticator, client_data};
use access_kernel::aas::ApprovalAct;
use access_kernel::combinator::Capacity;
use access_kernel::model::{Binding, Consumption, Independence, ProofKind, RequirementTerm};
use access_kernel::render;
use access_local_client::approve::{Approve, approve, push_only};
use access_local_client::login::{Jar, post_json};
use access_local_client::passkey::{Passkey, relying_party};
use access_sdk::agent::contract::{Proof, Step};
use access_sdk::approver::inline::{
    InlineRequest, PasskeyAssertion, StatementFacts, answer_body, approve_body,
    approve_to_be_signed, deny_to_be_signed, passkey_challenge, statement,
};
use access_sdk::approver::{registration_body, registration_message, thumbprint, to_raw_signature};
use access_store::authority::read_head;
use access_store::scope::DomainId;
use serde_json::Value;
use suiss_crypto::cose::PublicKey as CosePublicKey;
use suiss_crypto::signer::{Signer, SoftSigner};

use super::*;

/// WebAuthn authenticator data flags (WebAuthn L3 §6.1): user present, user verified.
const UP: u8 = 0x01;
const UV: u8 = 0x04;

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

    async fn audited(&self, event: &str) -> usize {
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let rows = t.audit_page(None, 10_000).await.unwrap();
        t.commit().await.unwrap();
        rows.iter().filter(|r| r.event_type == event).count()
    }

    async fn log_head(&self) -> u64 {
        read_head(&self.w.db.sequencer, &DomainId::from_bytes(self.domain.0))
            .await
            .unwrap()
            .pos
    }

    /// P's approval of `ex` on the hosted surface, as it answers.
    async fn hosted_approval(
        &self,
        ex: &Exercise,
        intent: &Value,
    ) -> Result<Value, access_local_client::ClientError> {
        let request = self.pushed_request(ex, intent).await;
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        approve(
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
        )
        .await
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

    /// Another active account of the realm with a registered passkey of its own, as the
    /// registration ceremony stores one: the key that answers for it.
    async fn someone_elses_passkey(&self) -> SoftSigner {
        use access_identity_account::adapters::pg::PgAccounts;
        use access_identity_account::app::Actor;
        use access_identity_account::app::accounts::{change_status, create};
        use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
        use access_identity_account::domain::status::AccountStatus;
        use access_identity_oauth::adapters::PgDirectory;
        use access_identity_oauth::ports::Directory as _;
        use access_identity_session::adapters::passkeys::PgPasskeys;
        use access_identity_session::domain::session::SessionPolicy;
        use access_identity_ui::ports::Kits as _;
        use access_identity_webauthn::domain::cose::CoseAlgorithm;
        use access_identity_webauthn::domain::credential::{AttestationKind, CredentialRecord};
        use access_identity_webauthn::domain::ids::{CredentialId, UserHandle};
        use access_identity_webauthn::domain::software::SOFTWARE_AAGUID;
        use access_identity_webauthn::ports::CredentialRegistry as _;

        use crate::login::{HsmKits, RealmKeks};

        const WHO: Actor<'static> = Actor {
            actor: "test",
            correlation: "test",
        };
        let entry = PgDirectory::new(self.w.db.router.clone())
            .by_slug("acme")
            .await
            .unwrap()
            .unwrap();
        let kits = HsmKits::new(
            RealmKeks::new(Arc::clone(&self.w.keys)),
            self.w.db.router.clone(),
            self.w.db.app.clone(),
            SessionPolicy::DEFAULT,
        );
        let kit = kits.kit(&entry).await.unwrap();
        let pg = PgAccounts::sealed(self.w.db.app.clone(), kit.vault());
        let realm = kit.realm();
        let id = Identifier::new(IdentifierKind::Email, "q@acme.test").unwrap();
        let q = create(&pg, &realm, &[id], &WHO).await.unwrap();
        for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
            change_status(&pg, &realm, q, to, &WHO).await.unwrap();
        }
        let mut handle = [0_u8; 64];
        for half in handle.chunks_mut(32) {
            half.copy_from_slice(&access_crypto::random::bytes::<32>().unwrap());
        }
        let mut t = TenantTx::begin(&self.w.db.app, kit.tenant, kit.realm)
            .await
            .unwrap();
        assert!(t.insert_user_handle(q, &handle).await.unwrap());
        t.commit().await.unwrap();
        let (key, _) = SoftSigner::generate_ed25519().unwrap();
        let CosePublicKey::Ed25519(public) = key.public_key() else {
            panic!("ed25519")
        };
        let authenticator = SoftwareAuthenticator::ed25519(public);
        let now_s = server_time(&self.w.db.app).await.unwrap() / 1_000;
        PgPasskeys {
            pool: &self.w.db.app,
            tenant: kit.tenant,
            kek: &*kit.kek,
            ids: &kit.ids,
        }
        .insert(&CredentialRecord {
            realm: kit.rp.realm,
            id: CredentialId::new(&authenticator.credential_id).unwrap(),
            user: UserHandle::from_bytes(handle),
            public_key: authenticator.cose_key(),
            alg: CoseAlgorithm::EdDsa,
            sign_count: 0,
            backup_eligible: false,
            backup_state: false,
            user_verified: true,
            aaguid: SOFTWARE_AAGUID,
            transports: vec![String::from("internal")],
            attestation: AttestationKind::None,
            cred_protect: None,
            discoverable: None,
            prf: None,
            created_at: now_s,
            last_used_at: None,
            deleted_at: None,
        })
        .await
        .unwrap();
        key
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

/// The assertion an app's platform passkey API returns for `key` over `challenge`, at the
/// realm's origin with `rp_id` and the authenticator data `flags`.
fn platform_assertion(
    d: &Desk,
    key: &dyn Signer,
    rp_id: &str,
    challenge: &[u8],
    flags: u8,
) -> PasskeyAssertion {
    let CosePublicKey::Ed25519(public) = key.public_key() else {
        panic!("ed25519")
    };
    let authenticator = SoftwareAuthenticator::ed25519(public);
    let (_, origin) = relying_party(&d.user.issuer).unwrap();
    let mut authenticator_data = authenticator.authenticator_data(rp_id, false);
    authenticator_data[32] = flags;
    let client_data_json = client_data("webauthn.get", challenge, &origin);
    let mut message = authenticator_data.clone();
    message.extend_from_slice(&access_crypto::webauthn::sha256(&client_data_json));
    PasskeyAssertion {
        credential_id: authenticator.credential_id.to_vec(),
        authenticator_data,
        client_data_json,
        signature: key.sign(&message).unwrap(),
        user_handle: None,
    }
}

/// Posts the device's signed approval with the passkey `assertion`.
async fn approve_with(
    d: &Desk,
    phone: &Phone,
    signed: &[u8],
    assertion: &PasskeyAssertion,
) -> (u16, Value) {
    let signature = to_raw_signature(&phone.key.sign(signed).unwrap()).unwrap();
    let mut browser = Jar::default();
    let answered = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&approve_body(signed, &signature, assertion)).unwrap()),
    )
    .await
    .unwrap();
    (answered.status, answered.json())
}

fn exercise_of(v: &Value) -> Digest {
    Digest(
        <[u8; 32]>::try_from(access_kernel::json::b64url_decode(v.as_str().unwrap()).unwrap())
            .unwrap(),
    )
}

/// Posts the device's signed answer.
async fn answer(d: &Desk, phone: &Phone, signed: &[u8]) -> (u16, Value) {
    let signature = to_raw_signature(&phone.key.sign(signed).unwrap()).unwrap();
    let mut browser = Jar::default();
    let answered = post_json(
        &d.http,
        &format!("{}/v1/approve/inline", d.user.issuer),
        &mut browser,
        Some(serde_json::from_str::<Value>(&answer_body(signed, &signature)).unwrap()),
    )
    .await
    .unwrap();
    (answered.status, answered.json())
}

// §10.2, §10.3.1, MD-11, SEC26, TN-100, §13.7.3, §8.17.6.3, OP-157 m.3 (m), X-L7, Ek B 5416, 5477, 5499, 5631
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_valid_device_statement_is_refused_and_records_nothing() {
    let d = Desk::open("v7-inline", false).await;
    let phone = d.phone().await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));

    d.root_change(Change::ApprovalInline(true)).await;
    let (status, pushed, env) = d.push_waiting(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{pushed}");
    assert_eq!(d.inline_sent().await, 1, "a separate template, X-L7");
    let (request, shown) = inline_request(&intent);
    assert_eq!(request.verified().unwrap(), shown);

    let act = d.inline_statement(&request, &env, &shown).await;
    let signed = approve_to_be_signed(&request, &act, &phone.print);
    let before = d.log_head().await;
    let (status, body) = answer(&d, &phone, &signed).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("approval-inline-assertion-required")),
        "{body}"
    );
    assert_eq!(d.log_head().await, before, "nothing is recorded");
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let (status, body) = answer(&d, &phone, &signed).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("approval-inline-assertion-required")),
        "{body}"
    );

    // C30
    let deny = deny_to_be_signed(&request, &phone.print);
    let (status, body) = answer(&d, &phone, &deny).await;
    assert_eq!(
        (status, body["decision"].as_str()),
        (200, Some("denied")),
        "{body}"
    );
    let (status, body) = answer(&d, &phone, &signed).await;
    assert_eq!(status, 404, "{body}");
    d.close().await;
}

// §10.2, §10.3.1, MD-11, SEC26, TN-100, §13.7.3, §8.17.6.3, OP-157 m.3 (m), m.17, C30, Ek B 5477, 5499, 5631
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ct1_approval_from_the_notification_counts_only_with_the_approvers_passkey_over_h_aas() {
    let d = Desk::open("v7b-inline", false).await;
    let phone = d.phone().await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    d.root_change(Change::ApprovalInline(true)).await;
    let (status, pushed, env) = d.push_waiting(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{pushed}");
    assert_eq!(d.inline_sent().await, 1);
    let (request, shown) = inline_request(&intent);
    let act = d.inline_statement(&request, &env, &shown).await;
    let signed = approve_to_be_signed(&request, &act, &phone.print);
    let challenge = passkey_challenge(&act).unwrap();
    let mut later = act.clone();
    later.expires_at -= 1;
    let elsewhere = passkey_challenge(&later).unwrap();
    let passkey = d.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
    let (rp_id, _) = relying_party(&d.user.issuer).unwrap();
    let (stranger, _) = SoftSigner::generate_ed25519().unwrap();
    let other = d.someone_elses_passkey().await;
    let before = d.log_head().await;

    // §10.2, MD-11
    let (status, body) = answer(&d, &phone, &signed).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("approval-inline-assertion-required")),
        "{body}"
    );
    // §10.3.1, OP-157 m.17
    for (why, assertion) in [
        (
            "another RP ID",
            platform_assertion(&d, &passkey, "elsewhere.test", &challenge, UP | UV),
        ),
        (
            "a challenge that is not H(AAS)",
            platform_assertion(&d, &passkey, &rp_id, &elsewhere, UP | UV),
        ),
        (
            "no user presence",
            platform_assertion(&d, &passkey, &rp_id, &challenge, UV),
        ),
        (
            "an unregistered passkey",
            platform_assertion(&d, &stranger, &rp_id, &challenge, UP | UV),
        ),
        (
            "another person's passkey",
            platform_assertion(&d, &other, &rp_id, &challenge, UP | UV),
        ),
    ] {
        let (status, body) = approve_with(&d, &phone, &signed, &assertion).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (401, Some("assertion-rejected")),
            "{why}: {body}"
        );
    }
    assert_eq!(
        d.log_head().await,
        before,
        "a refused answer records nothing"
    );
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));

    // OP-157 m.17
    let good = platform_assertion(&d, &passkey, &rp_id, &challenge, UP);
    let (status, body) = approve_with(&d, &phone, &signed, &good).await;
    assert_eq!(
        (status, body["decision"].as_str()),
        (200, Some("approved")),
        "{body}"
    );
    assert!(d.log_head().await > before, "the contribution is recorded");
    // OP-41
    assert_eq!(d.audited("approval.inline").await, 1);
    ex.prove(Proof::Contribution(exercise_of(&body["exercise"])))
        .unwrap();
    assert!(matches!(d.ask(&mut ex), Step::Proceed(_)));

    // C30
    let at = d.log_head().await;
    let (status, body) = approve_with(&d, &phone, &signed, &good).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (404, Some("approval-request-unknown")),
        "{body}"
    );
    assert_eq!(d.log_head().await, at);
    d.close().await;
}

// §10.3.1, §13.7.3, OP-157 m.17, Ek B 5477, 5631
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_term_that_asks_for_user_verification_refuses_a_presence_only_assertion() {
    let d = Desk::open("v7b-inline-uv", false).await;
    let phone = d.phone().await;
    let mut term = surface_term();
    term.independence = Independence::None;
    term.assurance
        .insert(String::from(access_kernel::assurance::UV), 1);
    let held = d.agent_grant_needing(term).await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    d.root_change(Change::ApprovalInline(true)).await;
    let (status, pushed, env) = d.push_waiting(&ex, &intent, |_| {}).await;
    assert_eq!(status, 201, "{pushed}");
    let (request, shown) = inline_request(&intent);
    let act = d.inline_statement(&request, &env, &shown).await;
    let signed = approve_to_be_signed(&request, &act, &phone.print);
    let challenge = passkey_challenge(&act).unwrap();
    let passkey = d.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
    let (rp_id, _) = relying_party(&d.user.issuer).unwrap();
    let before = d.log_head().await;
    let presence = platform_assertion(&d, &passkey, &rp_id, &challenge, UP);
    let (status, body) = approve_with(&d, &phone, &signed, &presence).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("assertion-rejected")),
        "{body}"
    );
    assert_eq!(d.log_head().await, before);
    let verified = platform_assertion(&d, &passkey, &rp_id, &challenge, UP | UV);
    let (status, body) = approve_with(&d, &phone, &signed, &verified).await;
    assert_eq!(
        (status, body["decision"].as_str()),
        (200, Some("approved")),
        "{body}"
    );
    ex.prove(Proof::Contribution(exercise_of(&body["exercise"])))
        .unwrap();
    assert!(matches!(d.ask(&mut ex), Step::Proceed(_)));
    d.close().await;
}

// §13.7.3, SEC26, TN-100, OP-157 m.3 (m), m.17, Ek B 5477, 5499, 5631
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ct2_request_is_only_invited_and_cannot_be_answered_from_a_notification() {
    let d = Desk::open("v7-inline-ct2", false).await;
    let phone = d.phone().await;
    let (_, held) = d.agent_grant().await;
    let mut intent = d.intent_json("main").await;
    intent["params"]["amount"] =
        serde_json::json!({ "amount": { "value": 1, "unit": "usd_cent" } });
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    d.root_change(Change::ApprovalInline(true)).await;
    let redirect = d.user.redirect_uri.clone();
    let (status, pushed, env) = d
        .push_waiting(&ex, &intent, |b| {
            b["redirect_uri"] = Value::from(redirect);
        })
        .await;
    assert_eq!(status, 201, "{pushed}");
    let invited = identity_events_until(
        &d.w.db,
        "relay.message.approval_requested.v1",
        |q| !q.is_empty(),
        "the invitation",
    )
    .await;
    assert_eq!(invited.len(), 1);
    let (request, shown) = inline_request(&intent);
    let act = d.inline_statement(&request, &env, &shown).await;
    let signed = approve_to_be_signed(&request, &act, &phone.print);
    let before = d.log_head().await;
    let (status, body) = answer(&d, &phone, &signed).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("approval-inline-off")),
        "{body}"
    );
    // OP-157 m.17
    let passkey = d.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
    let (rp_id, _) = relying_party(&d.user.issuer).unwrap();
    let assertion = platform_assertion(
        &d,
        &passkey,
        &rp_id,
        &passkey_challenge(&act).unwrap(),
        UP | UV,
    );
    let (status, body) = approve_with(&d, &phone, &signed, &assertion).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("approval-inline-off")),
        "{body}"
    );
    assert_eq!(d.log_head().await, before);
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
    let redirect = d.user.redirect_uri.clone();
    let (status, pushed, env) = d
        .push_waiting(&ex, &intent, |b| {
            b["redirect_uri"] = Value::from(redirect);
        })
        .await;
    assert_eq!(status, 201, "{pushed}");
    // X-L7
    let invited = identity_events_until(
        &d.w.db,
        "relay.message.approval_requested.v1",
        |q| !q.is_empty(),
        "the invitation",
    )
    .await;
    assert_eq!(invited.len(), 1);
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
    assert_eq!(answered.status, 409, "{}", answered.json());
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
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    d.set_policy_default_surfaces(&["suiss-approver-sdk"]).await;
    let refused = d
        .hosted_approval(&ex, &intent)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("approval-surface-not-accepted"),
        "{refused}"
    );
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
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

    // §13.7.3
    let (status, body) = start_batch(&d, &mut jar, &uris).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (422, Some("approval-batch-invalid")),
        "{body}"
    );
    d.root_change(Change::ApprovalBatch(true)).await;

    // §13.7.3
    let eleven = vec![uris[0].clone(); 11];
    let (status, body) = start_batch(&d, &mut jar, &eleven).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (422, Some("approval-batch-invalid")),
        "{body}"
    );

    // §13.7.3
    let other_intent = d.intent_json("c").await;
    let mut other = d.exercise(&other_intent, held);
    assert!(matches!(d.ask(&mut other), Step::Wait(_)));
    let someone = access_kernel::json::b64url_encode(&[0x77; 16]);
    let (status, pushed, _) = d
        .push_waiting(&other, &other_intent, |b| {
            b["request"]["requester"]["party"] = Value::from(someone);
        })
        .await;
    assert_eq!(status, 201, "{pushed}");
    let mixed = vec![
        uris[0].clone(),
        String::from(pushed["request_uri"].as_str().unwrap()),
    ];
    let (status, body) = start_batch(&d, &mut jar, &mixed).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (422, Some("approval-batch-invalid")),
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
