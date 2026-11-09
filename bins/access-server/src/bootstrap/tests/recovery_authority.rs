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
            origins: access_kernel::combinator::Origins::default(),
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
    // INV-40, OP-153 m.16 (d)
    let mut authority = access_authority_core::genesis::bootstrap_authority();
    authority
        .authority
        .actions
        .exact
        .insert(access_kernel::meta::core_action("mandate_rebind"));
    let envelope = |requirements: BTreeSet<RequirementTerm>| MandateEnvelope {
        origins: access_kernel::combinator::Origins::default(),
        authority: authority.authority.clone(),
        constraints: authority.constraints.clone(),
        requirements,
        pin: None,
    };
    let later = commit(
        &c,
        &successor,
        party,
        Payload::MandateBind {
            instance: succ,
            envelope: envelope(BTreeSet::new()),
        },
    )
    .await;
    assert_eq!(subcodes(&later).0, Some(Outcome::Allow), "{later:?}");
    let Verdict::Committed(bound) = &later else {
        panic!("{later:?}");
    };
    let mandate = access_kernel::meta::object_id(&bound.exercise, kind::MANDATE, 0);
    let weak_rebind = commit(
        &c,
        &successor,
        party,
        Payload::MandateRebind {
            mandate,
            envelope: envelope(BTreeSet::from([phishing_resistant()])),
        },
    )
    .await;
    assert_eq!(
        subcodes(&weak_rebind),
        (
            Some(Outcome::RequireAction),
            vec![String::from("recovery-too-weak")]
        ),
        "{weak_rebind:?}"
    );
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
    let app = hosted_with_devices(&c, Recording::default());
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
    let unlink = me
        .call(
            &app,
            &Method::DELETE,
            &format!("/v1/account/linked/{}", b64url_encode(&[7; 16])),
            None,
        )
        .await;
    assert_eq!(unlink.status, StatusCode::FORBIDDEN, "{}", unlink.json);
    assert_eq!(unlink.json["code"], "recovery-grace");

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

fn start_body(email: &str, method: &str) -> serde_json::Value {
    serde_json::json!({"identifier": email, "method": method})
}

// TN-52, TN-59, TN-61, OP-153 m.3 (d), (gg)
// TN-52, Ek B 3538, 3539, 3969
#[tokio::test]
async fn recovery_starts_only_with_the_nist_classes_and_registered_codes_are_spent_one_by_one() {
    let c = console("recovery-classes", false).await;
    let sent = Recording::default();
    let app = super::recovery::hosted(&c, sent.clone());
    let cara = account(&c, "cara@example.com", true).await;

    // TN-52
    for method in [
        "registered_code",
        "sent_code",
        "recovery_contact",
        "second_authenticator",
    ] {
        let mut p = Page::default();
        let r = p
            .call(
                &app,
                &Method::POST,
                "/v1/recovery",
                Some(start_body("nobody@example.com", method)),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{method}: {}", r.json);
    }
    for method in [
        "identity_reproofing",
        "reset_intent",
        "temporary_access_pass",
    ] {
        let mut p = Page::default();
        let r = p
            .call(
                &app,
                &Method::POST,
                "/v1/recovery",
                Some(start_body("nobody@example.com", method)),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{method}: {}", r.json);
    }

    // TN-59
    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(&c, cara).await,
    );
    let codes = me
        .call(&app, &Method::POST, "/v1/account/recovery-codes", None)
        .await;
    let codes: Vec<String> = codes.json["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    for code in &codes {
        let raw: String = code.chars().filter(char::is_ascii_alphanumeric).collect();
        // TN-59
        assert_eq!(raw.len(), 16, "{code}");
    }
    assert!(
        sent.sent()
            .iter()
            .any(|s| s.kind == "relay.message.recovery_codes_regenerated.v1"),
        "regeneration is notified"
    );
    // TN-59
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let stored = t.credentials(cara, "recovery_code").await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(stored.len(), 10);
    for s in &stored {
        for code in &codes {
            let raw: String = code.chars().filter(char::is_ascii_alphanumeric).collect();
            assert!(
                !s.sealed
                    .ciphertext
                    .windows(raw.len())
                    .any(|w| w == raw.as_bytes()),
                "a code is never kept in the clear"
            );
        }
    }

    // TN-59
    let mut page = Page::default();
    let started = page
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(start_body("cara@example.com", "registered_code")),
        )
        .await;
    let path = format!("/v1/recovery/{}", started.json["attempt"].as_str().unwrap());
    let used = page
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": codes[0]})),
        )
        .await;
    assert_eq!(used.status, StatusCode::OK, "{}", used.json);
    let replacement = used.json["replacement_code"].as_str().unwrap().to_owned();
    assert!(!codes.contains(&replacement));
    let mut again = Page::default();
    let second = again
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(start_body("cara@example.com", "registered_code")),
        )
        .await;
    let path = format!("/v1/recovery/{}", second.json["attempt"].as_str().unwrap());
    let other = again
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": codes[1]})),
        )
        .await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.json);
    let mut third = Page::default();
    let reuse = third
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(start_body("cara@example.com", "registered_code")),
        )
        .await;
    let path = format!("/v1/recovery/{}", reuse.json["attempt"].as_str().unwrap());
    let reused = third
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": codes[0]})),
        )
        .await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED, "{}", reused.json);
}

// TN-54, OP-153 m.3 (d), CR-40, (gg), Ek B 3544
#[tokio::test]
async fn starting_recoveries_never_locks_the_account_out() {
    let c = console("recovery-dos", false).await;
    let sent = Recording::default();
    let app = super::recovery::hosted(&c, sent.clone());
    let dina = account(&c, "dina@example.com", true).await;
    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(&c, dina).await,
    );
    let setup = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({"recovery_email": "dina.backup@example.net"})),
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.json);
    let mut answers = Vec::new();
    for _ in 0..5 {
        let mut p = Page::default();
        let r = p
            .call(
                &app,
                &Method::POST,
                "/v1/recovery",
                Some(start_body("dina@example.com", "sent_code")),
            )
            .await;
        answers.push(r.status);
    }
    // CR-40
    assert!(
        answers.iter().all(|s| *s == StatusCode::CREATED),
        "{answers:?}"
    );
    let codes = sent
        .sent()
        .iter()
        .filter(|s| s.to == "dina.backup@example.net" && s.kind == "relay.message.otp.v1")
        .count();
    assert_eq!(codes, 3, "three starts a day per account send codes");
    assert_eq!(
        super::recovery::audited(&c, "recovery.start_limited")
            .await
            .len(),
        2
    );
    // TN-54
    let still = me
        .call(&app, &Method::GET, "/v1/account/recovery-contacts", None)
        .await;
    assert_eq!(still.status, StatusCode::OK, "{}", still.json);
}

// TN-60, TNI-6, TN-62, OP-153 m.3 (f), (gg), Ek B 3549, 3913
#[tokio::test]
async fn turning_assisted_recovery_off_leaves_only_the_owners_own_codes() {
    let c = console("recovery-unassisted", false).await;
    let sent = Recording::default();
    let app = super::recovery::hosted(&c, sent.clone());
    let eve = account(&c, "eve@example.com", true).await;
    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(&c, eve).await,
    );
    let codes = me
        .call(&app, &Method::POST, "/v1/account/recovery-codes", None)
        .await;
    let code = codes.json["recovery_codes"][0].as_str().unwrap().to_owned();
    // TN-60
    let unacknowledged = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({
                "recovery_email": "eve.backup@example.net",
                "assisted_recovery": false
            })),
        )
        .await;
    assert_eq!(
        unacknowledged.status,
        StatusCode::BAD_REQUEST,
        "{}",
        unacknowledged.json
    );
    let off = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({
                "recovery_email": "eve.backup@example.net",
                "assisted_recovery": false,
                "permanent_loss_acknowledged": true
            })),
        )
        .await;
    assert_eq!(off.status, StatusCode::OK, "{}", off.json);
    assert_eq!(off.json["assisted_recovery"], false);

    // TN-60
    let mut p = Page::default();
    let r = p
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(start_body("eve@example.com", "sent_code")),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert!(
        !sent
            .sent()
            .iter()
            .any(|s| s.to == "eve.backup@example.net" && s.kind == "relay.message.otp.v1")
    );
    // TN-60
    let mut q = Page::default();
    let own = q
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(start_body("eve@example.com", "registered_code")),
        )
        .await;
    let path = format!("/v1/recovery/{}", own.json["attempt"].as_str().unwrap());
    let proved = q
        .call(
            &app,
            &Method::POST,
            &path,
            Some(serde_json::json!({"code": code})),
        )
        .await;
    assert_eq!(proved.status, StatusCode::OK, "{}", proved.json);

    // TNI-6
    for (method, route) in [
        (Method::POST, "/v1/account/totp"),
        (Method::POST, "/v1/account/recovery-codes"),
    ] {
        let g = q
            .call(&app, &method, route, Some(serde_json::json!({})))
            .await;
        assert_eq!(g.status, StatusCode::UNAUTHORIZED, "{route}: {}", g.json);
    }
}

/// Deletes `subject` with no window and writes its tombstone, as the retention job does.
async fn delete_now(c: &super::management::Console, subject: [u8; 16]) {
    use access_identity_account::app::privacy::{DeletionSource, request_deletion, tombstone_due};
    use access_identity_account::ports::{AccountDb as _, AccountTx as _};
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let v = super::recovery::vault_of(c);
    let realm = access_identity_account::app::Realm {
        tenant: c.route.tenant,
        realm: c.route.realm,
        kek: &*v.kek,
        ids: &ids,
    };
    let who = access_identity_account::app::Actor {
        actor: "test",
        correlation: "test",
    };
    let db =
        access_identity_account::adapters::pg::PgAccounts::sealed(c.w.db.app.clone(), v.clone());
    let mut tx = db.begin(realm.tenant, realm.realm).await.unwrap();
    request_deletion(
        &mut tx,
        &realm,
        subject,
        DeletionSource::SelfService,
        None,
        0,
        &who,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(tombstone_due(&db, &realm, &who).await.unwrap(), 1);
}

type Start = (StatusCode, Option<u64>, String, Vec<String>);

async fn neutral_start(app: &axum::Router, who: &str) -> Start {
    let mut p = Page::default();
    let mut r = p
        .call(
            app,
            &Method::POST,
            "/v1/recovery",
            Some(start_body(who, "registered_code")),
        )
        .await;
    assert!(r.json["attempt"].is_string(), "{}", r.json);
    r.json["attempt"] = serde_json::Value::from("*");
    (
        r.status,
        r.retry_after,
        r.json.to_string(),
        p.jar.keys().cloned().collect(),
    )
}

// 4091, 4107, 4110, 4111, 3662, CR-40, TN-54, TN-83, X-L11, OP-153 m.3 (d), (gg)
#[tokio::test]
async fn recovery_starts_answer_alike_for_live_unknown_and_deleted_accounts() {
    let c = console("recovery-parity", false).await;
    let sent = Recording::default();
    let app = super::recovery::hosted(&c, sent.clone());
    account(&c, "live@example.com", true).await;
    let gone = account(&c, "gone@example.com", true).await;
    delete_now(&c, gone).await;
    let mut answers = Vec::new();
    for who in ["live@example.com", "never@example.com", "gone@example.com"] {
        answers.push(neutral_start(&app, who).await);
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!(answers[0], answers[2]);
    assert_eq!(answers[0].0, StatusCode::CREATED);
    // TN-83, Ek B 4110
    let mut limited = Vec::new();
    for _ in 0..4 {
        limited.push(neutral_start(&app, "live@example.com").await);
    }
    assert!(limited.iter().all(|a| *a == answers[1]), "{limited:?}");
    assert_eq!(
        super::recovery::audited(&c, "recovery.start_limited")
            .await
            .len(),
        2,
        "three starts a day per account, then silence"
    );
    let to_live = sent
        .sent()
        .iter()
        .filter(|s| s.to == "live@example.com")
        .count();
    assert_eq!(to_live, 3);
    assert!(sent.sent().iter().all(|s| s.to != "gone@example.com"));
}

// 3541, OP-153 m.3 (d), TN-52, CR-40, OP-153 m.3 (gg)
#[tokio::test]
async fn a_contact_code_is_extended_once_by_a_day_before_it_runs_out() {
    let c = console("recovery-extend", false).await;
    let sent = Recording::default();
    let app = super::recovery::hosted(&c, sent.clone());
    let lea = account(&c, "lea@example.com", true).await;
    let mut me = Page::default();
    me.jar.insert(
        String::from("__Host-access-session"),
        session(&c, lea).await,
    );
    let setup = me
        .call(
            &app,
            &Method::PUT,
            "/v1/account/recovery-contacts",
            Some(serde_json::json!({
                "recovery_email": "lea.alt@example.net",
                "contacts": ["pal@example.org"],
            })),
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.json);
    let mut p = Page::default();
    let started = p
        .call(
            &app,
            &Method::POST,
            "/v1/recovery",
            Some(start_body("lea@example.com", "recovery_contact")),
        )
        .await;
    assert_eq!(started.status, StatusCode::CREATED, "{}", started.json);
    let attempt = started.json["attempt"].as_str().unwrap().to_owned();
    let id = <[u8; 16]>::try_from(b64url_decode(&attempt).unwrap()).unwrap();
    let expiry = |c: &super::management::Console| {
        let db = c.w.db.app.clone();
        let (tenant, realm) = (c.route.tenant, c.route.realm);
        async move {
            let mut t = TenantTx::begin(&db, tenant, realm).await.unwrap();
            let e = t.recovery_evidence(id).await.unwrap();
            t.commit().await.unwrap();
            e.into_iter().map(|e| e.expires_ms).collect::<Vec<_>>()
        }
    };
    let before = expiry(&c).await;
    assert_eq!(before.len(), 1, "one code for the one contact");
    let path = format!("/v1/recovery/{attempt}/extension");
    let first = p.call(&app, &Method::POST, &path, None).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.json);
    let after = expiry(&c).await;
    assert_eq!(after[0] - before[0], 86_400_000);
    let second = p.call(&app, &Method::POST, &path, None).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(second.json, first.json, "CR-40: the same view either way");
    assert_eq!(expiry(&c).await, after, "only once");
    assert_eq!(
        super::recovery::audited(&c, "recovery.contact_extended")
            .await
            .len(),
        1
    );
    let stranger = Page::default().call(&app, &Method::POST, &path, None).await;
    assert_eq!(stranger.status, StatusCode::GONE);
}
