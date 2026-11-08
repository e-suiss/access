//! Account recovery on the authority side end to end against the real router, the decision
//! point, PostgreSQL and the token (OP-153 m.3 (c), (gg), m.13 (e)): the realm issuer's
//! `recovery_result` names the successor key at `REBIND_OPEN`, the successor's self-signed
//! `instance_recover` is accepted only with that Claim, the predecessor ends and the successor
//! inherits nothing, a bind under a weaker recovery path asks to strengthen it (INV-40) and a
//! CT2+ Exercise of the new Instance waits 24 hours (SEC18).

#![allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "test code; short names for the console and the keys"
)]

use std::collections::BTreeSet;

use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_internal_api::idp::Verdict;
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis, cose_key,
    register_nonce, self_signed_intent,
};
use access_kernel::combinator::{Mode, Outcome};
use access_kernel::intent::intent_digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{InstanceState, MandateEnvelope, Payload, kind};
use access_kernel::model::{
    Binding as ProofBinding, Consumption, Id, Independence, ProofKind, RequirementTerm, Window,
};
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::TenantTx;
use axum::http::{Method, StatusCode};
use suiss_crypto::signer::SoftSigner;

use super::management::{Browser, console, now};
use super::recovery::{Page, Recording, account, courier, hosted_with_devices, session};
use super::*;
use crate::bootstrap::MetaExercises;

fn signer(key: SoftSigner) -> Browser {
    Browser {
        jar: Vec::new(),
        csrf: String::new(),
        key,
    }
}

fn window() -> Window {
    let at = now();
    Window {
        from: at - 1_000,
        until: at + 600_000,
    }
}

/// The AIS by `key` over the self-signed `payload` of `party` under the bootstrap Grant.
fn self_signed(
    key: &Browser,
    domain: Digest,
    nonce: &[u8],
    payload: &Payload,
    party: Id,
    w: Window,
) -> Vec<u8> {
    signed(
        key,
        domain,
        nonce,
        payload,
        party,
        w,
        bootstrap_basis(&domain),
    )
}

/// The AIS by `key` over the `payload` of `party` under `basis`.
fn signed(
    key: &Browser,
    domain: Digest,
    nonce: &[u8],
    payload: &Payload,
    party: Id,
    w: Window,
    basis: access_kernel::meta::ExerciseBasis,
) -> Vec<u8> {
    let intent = self_signed_intent(payload, party, w).unwrap();
    let ais = key.ais_for(
        IDENTITY_PEP,
        domain,
        nonce,
        intent_digest(&intent).unwrap(),
        Mode::Commit,
        basis,
    );
    b64url_decode(&ais).unwrap()
}

/// `subject`'s Party with its first device Instance, as a stepped-up session registers them.
async fn device(c: &super::management::Console, subject: [u8; 16], key: &Browser) -> (Id, Id) {
    let party = Id(access_crypto::random::bytes::<16>().unwrap());
    let challenge = access_crypto::random::bytes::<32>().unwrap();
    let w = window();
    let mut r = Registration {
        tenant: *c.route.tenant.as_bytes(),
        domain: c.domain,
        registrant: Registrant::Device {
            realm: *c.route.realm.as_bytes(),
            subject,
        },
        party,
        key: key.key.public_key(),
        register: None,
        create: SelfSigned {
            nonce: challenge.to_vec(),
            validity: w,
            ais: Vec::new(),
        },
        pep: String::from(IDENTITY_PEP),
        context: None,
    };
    let nonce = register_nonce(&challenge);
    let ais = self_signed(key, c.domain, &nonce, &r.register_payload(), party, w);
    r.register = Some(SelfSigned {
        nonce,
        validity: w,
        ais,
    });
    r.create.ais = self_signed(key, c.domain, &challenge, &r.create_payload(), party, w);
    let RegistrationVerdict::Registered(done) =
        access_identity_ui::ports::DeviceInstances::register(&c.w.plane, r)
            .await
            .unwrap()
    else {
        panic!("not registered");
    };
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &subject, &party.0)
            .await
            .unwrap()
    );
    let access_kernel::verify::cose::PublicKey::P256(raw) = key.key.public_key() else {
        panic!("p-256");
    };
    access_store::issuer::insert_device_key(
        &mut t,
        &access_store::issuer::NewDeviceKey {
            subject,
            public_key: &raw,
            key_type: "EC2",
            algorithm: "ES256",
            instance: done.instance.0,
            session: None,
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    (party, done.instance)
}

/// The Instance `id` as the governing domain holds it.
async fn instance(c: &super::management::Console, id: Id) -> Option<InstanceState> {
    let key = access_kernel::meta::key(kind::INSTANCE, &id);
    access_store::authority::state_of(
        &c.w.db.app,
        &access_store::scope::DomainId::from_bytes(c.domain.0),
        &[key],
    )
    .await
    .unwrap()
    .into_iter()
    .find_map(|r| r.value)
    .map(|v| {
        <InstanceState as access_kernel::codec::Canonical>::from_value(
            &suiss_crypto::dcbor::decode(&v, suiss_crypto::dcbor::Limits::CEILING).unwrap(),
        )
        .unwrap()
    })
}

/// Steps the courier until the attempt's `recovery_result` is issued: the outbox only shows an
/// order once no older transaction of the cluster is open.
async fn drain(c: &super::management::Console, subject: [u8; 16], attempt: [u8; 16]) {
    let k = courier(c);
    let line = access_identity_account::domain::claims::recovery_result_line(&attempt);
    let domain = access_store::scope::DomainId::from_bytes(c.domain.0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let r = k.step().await.unwrap();
        let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
            .await
            .unwrap();
        let issued = access_store::issuer::last_in_line(&mut t, &subject, &domain, &line)
            .await
            .unwrap();
        t.commit().await.unwrap();
        if issued.is_some() {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{r:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A `mandate_bind` of `instance` signed by `key` with `requirements`, committed as the identity
/// plane's PEP.
async fn bind(
    c: &super::management::Console,
    key: &Browser,
    party: Id,
    instance: Id,
    requirements: BTreeSet<RequirementTerm>,
) -> Verdict {
    let authority = access_authority_core::genesis::bootstrap_authority();
    let payload = Payload::MandateBind {
        instance,
        envelope: MandateEnvelope {
            authority: authority.authority,
            constraints: authority.constraints,
            requirements,
            pin: None,
        },
    };
    commit(c, key, party, payload).await
}

/// `payload` signed by `key` for `party` under the meta-anchor, committed as the identity
/// plane's PEP.
async fn commit(
    c: &super::management::Console,
    key: &Browser,
    party: Id,
    payload: Payload,
) -> Verdict {
    let w = window();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let intent = self_signed_intent(&payload, party, w).unwrap();
    // OP-141 m.3
    let basis =
        access_kernel::meta::ExerciseBasis::Anchor(access_kernel::meta::meta_anchor(&c.domain));
    let ais = signed(key, c.domain, &nonce, &payload, party, w, basis);
    MetaExercises::meta(
        &c.w.plane,
        access_authority_core::domain::Request {
            domain: c.domain,
            mode: Mode::Commit,
            nonce: nonce.to_vec(),
            intent,
            payload: Some(payload),
            basis,
            capacity: access_kernel::combinator::Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais,
        String::from(IDENTITY_PEP),
    )
    .await
    .unwrap()
}

fn subcodes(v: &Verdict) -> (Option<Outcome>, Vec<String>) {
    match v {
        Verdict::NotAllowed { decision, .. } => (
            Some(decision.outcome),
            decision
                .blockers
                .iter()
                .filter_map(|b| b.subcode.clone())
                .collect(),
        ),
        Verdict::Committed(_) => (Some(Outcome::Allow), Vec::new()),
        Verdict::Refused { code, .. } => (None, vec![code.clone()]),
    }
}

fn phishing_resistant() -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: String::from("authentication"),
        count: 1,
        binding: ProofBinding::None,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: std::collections::BTreeMap::from([(
            String::from(access_kernel::assurance::PHISHING_RESISTANT),
            1,
        )]),
    }
}

/// The `instance_recover` body `successor` signs for the terms a recovery step answered.
fn recovery_body(
    terms: &serde_json::Value,
    successor: &Browser,
    domain: Digest,
) -> serde_json::Value {
    let party =
        Id(<[u8; 16]>::try_from(b64url_decode(terms["party"].as_str().unwrap()).unwrap()).unwrap());
    let predecessor = Id(<[u8; 16]>::try_from(
        b64url_decode(terms["predecessor"].as_str().unwrap()).unwrap(),
    )
    .unwrap());
    let payload = Payload::InstanceRecover {
        instance: predecessor,
        key: successor.key.public_key(),
    };
    let w = window();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let ais = self_signed(successor, domain, &nonce, &payload, party, w);
    serde_json::json!({
        "key": b64url_encode(&cose_key(&successor.key.public_key())),
        "nonce": b64url_encode(&nonce),
        "valid_from": access_identity_ui::domain::frontend::rfc3339(w.from),
        "valid_until": access_identity_ui::domain::frontend::rfc3339(w.until),
        "ais": b64url_encode(&ais),
    })
}

// OP-153 m.3 (c), m.13 (e), INV-13, INV-40, SEC18, TN-53, C8, X38, OP-153 m.3 (gg)
// TN-53, Ek B 3528, 3530, 3532, 3533, 3545, 4029
#[tokio::test]
async fn a_recovered_successor_is_bound_by_its_recovery_result() {
    let c = console("recovery-authority", false).await;
    let sent = Recording::default();
    let app = hosted_with_devices(&c, sent.clone());
    let rae = account(&c, "rae@example.com", true).await;
    let old = signer(SoftSigner::generate_p256().unwrap().0);
    let (party, predecessor) = device(&c, rae, &old).await;

    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(&c, rae).await,
    );
    let setup = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({"recovery_email": "rae.backup@example.net"})),
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.json);

    // §5.6
    let other = signer(SoftSigner::generate_p256().unwrap().0);
    let added = bind(&c, &old, party, predecessor, BTreeSet::new()).await;
    assert_eq!(subcodes(&added).0, Some(Outcome::Allow), "{added:?}");

    let mut thief = Page::default();
    let started = thief
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(serde_json::json!({"identifier": "rae@example.com", "method": "sent_code"})),
        )
        .await;
    assert_eq!(started.status, StatusCode::CREATED, "{}", started.json);
    let attempt = started.json["attempt"].as_str().unwrap().to_owned();
    let id = <[u8; 16]>::try_from(b64url_decode(&attempt).unwrap()).unwrap();
    let path = format!("/v1/recovery/{attempt}");
    let code = sent.last_code_to("rae.backup@example.net");
    let met = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": code})),
        )
        .await;
    assert_eq!(met.json["state"], "cooling_down", "{}", met.json);
    access_store::testing::age_recovery(&c.w.db, id)
        .await
        .unwrap();
    let open = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"resume": true})),
        )
        .await;
    assert_eq!(open.json["state"], "rebind_open", "{}", open.json);

    // OP-153 m.3 (c)
    let successor = signer(SoftSigner::generate_p256().unwrap().0);
    let named = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({
                "successor_key": b64url_encode(&cose_key(&successor.key.public_key()))
            })),
        )
        .await;
    assert_eq!(named.status, StatusCode::OK, "{}", named.json);
    assert_eq!(named.json["state"], "rebind_open");
    assert_eq!(named.json["party"], b64url_encode(&party.0));
    assert_eq!(named.json["predecessor"], b64url_encode(&predecessor.0));
    assert_eq!(named.json["domain"], b64url_encode(&c.domain.0));
    assert_eq!(named.json["pep"], IDENTITY_PEP);
    let bound = thief
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"new_password": "a new long passphrase"})),
        )
        .await;
    assert_eq!(bound.json["state"], "grace_period", "{}", bound.json);

    // OP-153 m.3 (c)
    let early = thief
        .call(
            &app,
            &Method::POST,
            "/v1/me/instances/recover",
            Some(recovery_body(&named.json, &successor, c.domain)),
        )
        .await;
    assert_eq!(early.status, StatusCode::CONFLICT, "{}", early.json);
    assert_eq!(early.json["code"], "recovery-result-pending");
    drain(&c, rae, id).await;

    // OP-153 m.3 (c)
    let unnamed = thief
        .call(
            &app,
            &Method::POST,
            "/v1/me/instances/recover",
            Some(recovery_body(&named.json, &other, c.domain)),
        )
        .await;
    assert_eq!(unnamed.status, StatusCode::CONFLICT, "{}", unnamed.json);
    assert_eq!(unnamed.json["code"], "recovery-key-not-named");
    assert!(instance(&c, predecessor).await.unwrap().ended.is_none());

    // INV-13, C8, SEC26, §13.7.3, Ek B 3530
    let body = recovery_body(&named.json, &successor, c.domain);
    let locked = thief
        .call(
            &app,
            &Method::POST,
            "/v1/me/instances/recover",
            Some(body.clone()),
        )
        .await;
    assert_eq!(locked.status, StatusCode::ACCEPTED, "{}", locked.json);
    assert!(locked.json["after"].is_string());
    assert!(instance(&c, predecessor).await.unwrap().ended.is_none());
    access_store::testing::age_authority(&c.w.db, c.domain.0, DAY_MS + 3_600_000)
        .await
        .unwrap();
    let recovered = thief
        .call(&app, &Method::POST, "/v1/me/instances/recover", Some(body))
        .await;
    assert_eq!(recovered.status, StatusCode::CREATED, "{}", recovered.json);
    assert_eq!(
        recovered.json["kid"],
        b64url_encode(&thumbprint(&successor.key.public_key()))
    );
    let succ = Id(<[u8; 16]>::try_from(
        b64url_decode(recovered.json["instance"].as_str().unwrap()).unwrap(),
    )
    .unwrap());
    let old_state = instance(&c, predecessor).await.unwrap();
    assert_eq!(old_state.successor, Some(succ));
    assert!(old_state.ended.is_some());
    let new_state = instance(&c, succ).await.unwrap();
    assert_eq!(new_state.party, party);
    assert!(new_state.ended.is_none());
    // INV-13, Ek B 4029
    let mandates = access_store::authority::state_of(
        &c.w.db.app,
        &access_store::scope::DomainId::from_bytes(c.domain.0),
        &[access_kernel::meta::key(kind::MANDATES, &succ)],
    )
    .await
    .unwrap();
    assert!(mandates.iter().all(|r| r.value.is_none()), "{mandates:?}");
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert_eq!(
        access_store::issuer::subject_instance(&mut t, &rae)
            .await
            .unwrap(),
        Some(succ.0)
    );
    let kept = t.recovery_rebind(id).await.unwrap().unwrap();
    assert_eq!(kept.predecessor, predecessor.0);
    assert!(kept.claim.is_some());
    t.commit().await.unwrap();

    // INV-40, TN-53
    let weak = bind(
        &c,
        &successor,
        party,
        succ,
        BTreeSet::from([phishing_resistant()]),
    )
    .await;
    assert_eq!(
        subcodes(&weak),
        (
            Some(Outcome::RequireAction),
            vec![String::from("recovery-too-weak")]
        ),
        "{weak:?}"
    );
    // SEC18
    let early = bind(&c, &successor, party, succ, BTreeSet::new()).await;
    assert_eq!(
        subcodes(&early),
        (Some(Outcome::RequireAction), vec![String::from("cooling")]),
        "{early:?}"
    );
    let Verdict::NotAllowed { decision, .. } = &early else {
        panic!("{early:?}");
    };
    let access_kernel::combinator::Remediation::WaitUntil(at) = decision.blockers[0].remediation
    else {
        panic!("{decision:?}");
    };
    assert!(at >= now() + 86_000_000, "{at}");
    access_store::testing::age_authority(&c.w.db, c.domain.0, DAY_MS + 3_600_000)
        .await
        .unwrap();
    // INV-40, Ek B 3528
    let mut ct3 = phishing_resistant();
    ct3.assurance
        .insert(String::from(access_kernel::assurance::HARDWARE_BOUND), 1);
    let mut authority = access_authority_core::genesis::bootstrap_authority();
    authority.requirements = BTreeSet::from([ct3]);
    let grant = Payload::GrantIssue(access_kernel::meta::GrantContent {
        basis: access_kernel::meta::GrantBasis::Anchor(access_kernel::meta::meta_anchor(&c.domain)),
        holder: access_kernel::model::SubjectSelector::Party(party),
        authority,
        agency: BTreeSet::from([access_kernel::combinator::Capacity::Own]),
        named: None,
    });
    let issued = commit(&c, &c.browser, c.root, grant).await;
    assert_eq!(
        subcodes(&issued),
        (
            Some(Outcome::RequireAction),
            vec![String::from("recovery-too-weak")]
        ),
        "{issued:?}"
    );
    // INV-40, SEC18
    let still = bind(
        &c,
        &successor,
        party,
        succ,
        BTreeSet::from([phishing_resistant()]),
    )
    .await;
    assert_eq!(
        subcodes(&still).1,
        vec![String::from("recovery-too-weak")],
        "{still:?}"
    );
    let later = bind(&c, &successor, party, succ, BTreeSet::new()).await;
    assert_eq!(subcodes(&later).0, Some(Outcome::Allow), "{later:?}");
}

const DAY_MS: u64 = 86_400_000;

/// Puts `subject` in the grace period after a recovery, as a rebind leaves it (TN-54).
async fn graced(c: &super::management::Console, subject: [u8; 16]) {
    use access_store::recovery::{NewAttempt, NewTransition};
    let at = i64::try_from(now()).unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let id = t
        .insert_recovery_attempt(&NewAttempt {
            subject: Some(subject),
            handle_hash: &access_crypto::random::bytes::<32>().unwrap(),
            path: "registered_code",
            required_aal: "aal1",
            cooling: b"{}",
            high_value: false,
            at_ms: at,
        })
        .await
        .unwrap();
    let evidence = vec![String::from("registered_code")];
    for (seq, state, until) in [
        (0, "requested", None),
        (1, "evidence_met", None),
        (2, "rebind_open", None),
        (3, "grace_period", Some(at + 86_400_000)),
    ] {
        t.insert_recovery_transition(
            id,
            &NewTransition {
                seq,
                state,
                required_aal: Some("aal1"),
                achieved_aal: (seq > 0).then_some("aal1"),
                evidence: if seq > 0 { &evidence } else { &[] },
                reason: "test",
                until_ms: until,
                at_ms: at,
            },
        )
        .await
        .unwrap();
    }
    t.commit().await.unwrap();
}

// TN-56, OP-153 m.3 (e), (gg), Ek B 3465
#[tokio::test]
async fn the_grace_period_holds_the_remaining_surfaces() {
    let c = console("recovery-grace-surfaces", false).await;
    let app = super::recovery::hosted(&c, Recording::default());
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let founder = ids
        .encode(access_identity_account::app::SUBJECT_PREFIX, c.subject)
        .unwrap();
    graced(&c, c.subject).await;

    // TN-56
    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(&c, c.subject).await,
    );
    let change = me
        .call(
            &app,
            &Method::POST,
            "/v1/account/email",
            Some(serde_json::json!({"email": "founder.new@example.com"})),
        )
        .await;
    assert_eq!(change.status, StatusCode::FORBIDDEN, "{}", change.json);
    assert_eq!(change.json["code"], "recovery-grace");
    assert!(change.retry_after.unwrap() > 86_000);

    // TN-56
    let (status, body) = super::recovery::admin_write(
        &c,
        "deleteAccount",
        Some(&founder),
        &format!("/admin/realms/acme/accounts/{founder}/delete"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "recovery-grace");
}

/// A recovery of `email` (password and recovery codes enrolled) proved with a registered code
/// and the password: the end of its objection window, `None` when the rebind opened at once.
async fn two_channel_cooling(
    c: &super::management::Console,
    app: &axum::Router,
    email: &str,
) -> Option<u64> {
    let subject = account(c, email, true).await;
    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(c, subject).await,
    );
    let codes = me
        .call(app, &Method::POST, "/v1/account/recovery-codes", None)
        .await;
    assert_eq!(codes.status, StatusCode::OK, "{}", codes.json);
    let code = codes.json["recovery_codes"][0].as_str().unwrap().to_owned();
    let mut page = Page::default();
    let started = page
        .call(
            app,
            &Method::POST,
            "/v1/recovery",
            Some(serde_json::json!({"identifier": email, "method": "registered_code"})),
        )
        .await;
    let path = format!("/v1/recovery/{}", started.json["attempt"].as_str().unwrap());
    let first = page
        .call(
            app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": code})),
        )
        .await;
    assert_eq!(first.json["state"], "requested", "{}", first.json);
    let second = page
        .call(
            app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"password": "correct horse battery staple"})),
        )
        .await;
    if second.json["state"] == "rebind_open" {
        return None;
    }
    assert_eq!(second.json["state"], "cooling_down", "{}", second.json);
    access_identity_ui::domain::frontend::unix_ms(second.json["until"].as_str().unwrap())
}

// RR-45, TN-17, TN-55, OP-153 m.13 (e), (gg)
#[tokio::test]
async fn recovery_is_tightened_after_an_rp_id_change() {
    let c = console("recovery-rp-id", false).await;
    let app = super::recovery::hosted(&c, Recording::default());
    // TN-55
    assert_eq!(two_channel_cooling(&c, &app, "ann@example.com").await, None);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    t.insert_rp_id_change(None, "access.test").await.unwrap();
    t.commit().await.unwrap();
    let after = two_channel_cooling(&c, &app, "ben@example.com")
        .await
        .unwrap();
    assert!(after >= now() + DAY_MS - 60_000, "{after}");
}
