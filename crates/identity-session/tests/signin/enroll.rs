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
