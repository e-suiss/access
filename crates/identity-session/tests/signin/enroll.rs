//! The first second factor enrolled at sign-in (OP-159 m.48 (a)) on the real flow.

use access_identity_session::app::STEP_NOT_ALLOWED;

use super::*;

fn required(mut e: Env) -> Env {
    e.policy = AuthPolicy {
        mfa: MfaPolicy::Required,
        ..AuthPolicy::DEFAULT
    };
    e
}

async fn enrollment(
    e: &Env,
    flow: &(String, String),
) -> Result<(String, Option<serde_json::Value>), Step> {
    e.with(async |a| {
        let f = flow.clone();
        a.sign_in_enrollment(&ref_of(&f), "Acme", "alice@example.com")
            .await
    })
    .await
    .unwrap()
    .map(|s| (s.totp.secret.expose().clone(), s.passkey))
}

// OP-159 m.48 (a), TN-64, §10.2.2
#[tokio::test]
async fn an_account_without_a_second_factor_enrolls_one_at_a_required_sign_in() {
    let e = env(62, "is-en1").await;
    e.account("alice@example.com").await;
    let other = sign_in(&e, "alice@example.com").await;
    let e = required(e);
    let flow = start(&e, Some("alice@example.com"), None).await;
    let before = enrollment(&e, &flow).await;
    assert!(
        matches!(before, Err(Step::Rejected(Refusal { problem, .. })) if problem == STEP_NOT_ALLOWED)
    );
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs == &[Requirement::EnrollSecondFactor])
    );
    let (secret, passkey) = enrollment(&e, &flow)
        .await
        .unwrap_or_else(|s| panic!("{s:?}"));
    assert!(passkey.is_some());
    let (again, _) = enrollment(&e, &flow)
        .await
        .unwrap_or_else(|s| panic!("{s:?}"));
    assert_eq!(again, secret);
    let seed = base32_decode(&secret);
    let wrong = e
        .with(async |a| {
            let f = flow.clone();
            a.confirm_sign_in_totp(&ref_of(&f), "000000", "req").await
        })
        .await
        .unwrap();
    assert!(
        matches!(wrong.step, Step::Rejected(Refusal { problem, .. }) if problem == CODE_NOT_ACCEPTED)
    );
    assert!(wrong.recovery_codes.is_none());
    e.advance(30_000);
    let code = totp_now(&e, &seed);
    let done = e
        .with(async |a| {
            let f = flow.clone();
            let c = code.clone();
            a.confirm_sign_in_totp(&ref_of(&f), &c, "req").await
        })
        .await
        .unwrap();
    assert_eq!(done.recovery_codes.as_ref().map(Vec::len), Some(10));
    let (cookie, s) = signed_in(done.step);
    assert_eq!(s.result.methods, [MethodClass::Password, MethodClass::Totp]);
    assert_eq!(s.result.assurance.aal, Aal::Aal2);
    assert!(matches!(status(&e, &cookie).await, SessionStatus::Valid(_)));
    assert!(matches!(
        status(&e, &other).await,
        SessionStatus::Invalid(SessionCheck::Ended)
    ));

    let next = start(&e, Some("alice@example.com"), None).await;
    let step = password(&e, &next, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs == &[Requirement::SecondFactor])
    );
    assert!(
        matches!(enrollment(&e, &next).await, Err(Step::Rejected(Refusal { problem, .. })) if problem == STEP_NOT_ALLOWED)
    );
    let refused = e
        .with(async |a| {
            let f = next.clone();
            let c = code.clone();
            a.confirm_sign_in_totp(&ref_of(&f), &c, "req").await
        })
        .await
        .unwrap();
    assert!(
        matches!(refused.step, Step::Rejected(Refusal { problem, .. }) if problem == STEP_NOT_ALLOWED)
    );
}

// OP-159 m.48 (a)
#[tokio::test]
async fn an_account_that_had_a_second_factor_cannot_add_one_at_sign_in() {
    let e = env(63, "is-en2").await;
    let alice = e.account("alice@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    let (_, _) = enable_totp(&e, &cookie).await;
    let totp = e
        .with(async |a| a.sign_in_methods(alice).await)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.kind == "totp")
        .unwrap();
    e.with(async |a| a.remove_method(alice, totp.id, "req").await)
        .await
        .unwrap()
        .unwrap();
    let e = required(e);
    let flow = start(&e, Some("alice@example.com"), None).await;
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs == &[Requirement::EnrollSecondFactor])
    );
    assert!(
        matches!(enrollment(&e, &flow).await, Err(Step::Rejected(Refusal { problem, .. })) if problem == STEP_NOT_ALLOWED)
    );
}

// OP-159 m.48 (a)
#[tokio::test]
async fn an_optional_second_factor_opens_no_enrollment() {
    let e = env(64, "is-en3").await;
    e.account("alice@example.com").await;
    let flow = start(&e, Some("alice@example.com"), None).await;
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(matches!(step, Step::SignedIn(_)));
    let flow = start(&e, Some("alice@example.com"), None).await;
    assert!(
        matches!(enrollment(&e, &flow).await, Err(Step::Rejected(Refusal { problem, .. })) if problem == STEP_NOT_ALLOWED)
    );
}

// OP-159 m.48 (a)
#[tokio::test]
async fn a_passkey_enrolled_at_sign_in_completes_it_with_its_assertion() {
    let e = required(env(65, "is-en4").await);
    e.account("alice@example.com").await;
    let flow = start(&e, Some("alice@example.com"), None).await;
    password(&e, &flow, "alice@example.com", PW).await;
    let (_, options) = enrollment(&e, &flow)
        .await
        .unwrap_or_else(|s| panic!("{s:?}"));
    let options = options.unwrap();
    let mut auth = Authenticator::new(Key::es256());
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let handle = b64url_decode(options["user"]["id"].as_str().unwrap()).unwrap();
    let (cdj, att) = auth.register(RP_ID, ORIGIN, &challenge);
    let id = auth.credential_id.clone();
    let outcome = e
        .with(async |a| {
            let f = flow.clone();
            a.enroll_sign_in_passkey(
                &ref_of(&f),
                &RegistrationResponse {
                    raw_id: &id,
                    client_data_json: &cdj,
                    attestation_object: &att,
                    transports: &[],
                    extensions: ClientExtensionResults::default(),
                },
                "req",
            )
            .await
        })
        .await
        .unwrap()
        .unwrap_or_else(|s| panic!("{s:?}"));
    assert!(matches!(outcome, RegistrationOutcome::Registered(_)));
    let step = e
        .with(async |a| {
            let f = flow.clone();
            a.resume(&ref_of(&f), "req").await
        })
        .await
        .unwrap();
    let Step::Continue { needs, enrolled } = step else {
        panic!("{step:?}");
    };
    assert_eq!(needs, [Requirement::SecondFactor]);
    assert!(enrolled.unwrap().passkeys);
    let request = e
        .with(async |a| {
            let f = flow.clone();
            a.passkey_options(&ref_of(&f), None).await
        })
        .await
        .unwrap()
        .unwrap();
    let step = assert_passkey(&e, &flow, &request, &mut auth, &handle).await;
    let (_, s) = signed_in(step);
    assert!(s.result.methods.contains(&MethodClass::Passkey));
}

// OP-159 m.49 (c), TN-144
#[tokio::test]
async fn a_sign_in_whose_client_asks_for_a_second_factor_enrolls_one_whatever_the_policy() {
    let e = env(65, "is-en4").await;
    e.account("alice@example.com").await;
    let s = e
        .with(async |a| {
            a.identify(&Identify {
                identifier: Some("alice@example.com"),
                second_factor: true,
                ..Identify::default()
            })
            .await
        })
        .await
        .unwrap();
    let flow = (s.handle, s.device);
    assert!(
        e.with(async |a| {
            let f = flow.clone();
            a.wants_second_factor(&ref_of(&f)).await
        })
        .await
        .unwrap()
    );
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs.first() == Some(&Requirement::EnrollSecondFactor))
    );
    assert!(enrollment(&e, &flow).await.is_ok());

    let plain = start(&e, Some("alice@example.com"), None).await;
    assert!(
        !e.with(async |a| {
            let f = plain.clone();
            a.wants_second_factor(&ref_of(&f)).await
        })
        .await
        .unwrap()
    );
    assert!(matches!(
        password(&e, &plain, "alice@example.com", PW).await,
        Step::SignedIn(_)
    ));
}

/// Revokes `subject`'s authenticator app as an account recovery does (TN-167).
async fn lost_to_recovery(e: &Env, subject: [u8; 16]) {
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.environment)
        .await
        .unwrap();
    assert_eq!(
        tx.revoke_by_recovery(subject, "totp").await.unwrap().len(),
        1
    );
    tx.commit().await.unwrap();
}

/// Opens `subject`'s grace period after a recovery until `until_ms` (TN-56).
async fn in_grace(e: &Env, subject: [u8; 16], until_ms: i64) {
    let now = i64::try_from(e.clock.now_ms()).unwrap();
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.environment)
        .await
        .unwrap();
    let attempt = tx
        .insert_recovery_attempt(&access_store::recovery::NewAttempt {
            subject: Some(subject),
            handle_hash: &[9; 32],
            path: "reset_intent",
            required_aal: "aal1",
            cooling: &[0; 2],
            high_value: false,
            at_ms: now,
        })
        .await
        .unwrap();
    tx.insert_recovery_transition(
        attempt,
        &access_store::recovery::NewTransition {
            seq: 0,
            state: "grace_period",
            required_aal: Some("aal1"),
            achieved_aal: Some("aal1"),
            evidence: &[],
            reason: "authenticator_bound",
            until_ms: Some(until_ms),
            at_ms: now,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

// TN-167, OP-159 m.48 (a)
#[tokio::test]
async fn an_app_lost_to_a_recovery_is_set_up_again_at_sign_in_once_the_grace_period_ends() {
    let e = env(0x67, "is-en167").await;
    let alice = e.account("alice@example.com").await;
    let cookie = sign_in(&e, "alice@example.com").await;
    let (_, _) = enable_totp(&e, &cookie).await;
    lost_to_recovery(&e, alice).await;
    let until = i64::try_from(e.clock.now_ms()).unwrap() + 86_400_000;
    in_grace(&e, alice, until).await;
    let e = required(e);

    let flow = start(&e, Some("alice@example.com"), None).await;
    let step = password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(step, Step::Continue { ref needs, .. } if needs == &[Requirement::EnrollSecondFactor])
    );
    assert!(
        matches!(enrollment(&e, &flow).await, Err(Step::Rejected(Refusal { problem, .. })) if problem == STEP_NOT_ALLOWED),
        "not while the grace period runs"
    );

    e.advance(86_400_001);
    let flow = start(&e, Some("alice@example.com"), None).await;
    password(&e, &flow, "alice@example.com", PW).await;
    let (secret, _) = enrollment(&e, &flow)
        .await
        .unwrap_or_else(|s| panic!("{s:?}"));
    let code = totp_now(&e, &base32_decode(&secret));
    let done = e
        .with(async |a| {
            let f = flow.clone();
            let c = code.clone();
            a.confirm_sign_in_totp(&ref_of(&f), &c, "req").await
        })
        .await
        .unwrap();
    let (_, s) = signed_in(done.step);
    assert_eq!(s.result.methods, [MethodClass::Password, MethodClass::Totp]);

    let methods = e
        .with(async |a| a.sign_in_methods(alice).await)
        .await
        .unwrap();
    let totp = methods.into_iter().find(|m| m.kind == "totp").unwrap();
    e.with(async |a| a.remove_method(alice, totp.id, "req").await)
        .await
        .unwrap()
        .unwrap();
    let flow = start(&e, Some("alice@example.com"), None).await;
    password(&e, &flow, "alice@example.com", PW).await;
    assert!(
        matches!(enrollment(&e, &flow).await, Err(Step::Rejected(Refusal { problem, .. })) if problem == STEP_NOT_ALLOWED),
        "a removal after the recovery counts again"
    );
}
