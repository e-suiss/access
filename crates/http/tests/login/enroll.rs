//! The management defaults and the first second factor at sign-in on the hosted surface (OP-159
//! m.48 (a), (c)).

use access_identity_session::domain::environment_policy::Registration;
use access_identity_session::domain::requirement::{AuthPolicy, MfaPolicy};

use super::*;

const REQUIRED: AuthPolicy = AuthPolicy {
    mfa: MfaPolicy::Required,
    ..AuthPolicy::DEFAULT
};

fn node<'a>(a: &'a Value, kind: &str) -> Option<&'a Value> {
    a["nodes"].as_array()?.iter().find(|n| n["type"] == kind)
}

// OP-159 m.48 (c)
#[tokio::test]
async fn an_invite_only_environment_refuses_open_registration() {
    let signin = EnvironmentSignin {
        registration: Registration::InviteOnly,
        ..EnvironmentSignin::default()
    };
    let e = env_full(0xd1, "m48-closed", AuthPolicy::DEFAULT, false, signin).await;
    let mut b = e.browser("m48-closed");
    let refused = b
        .post("/v1/login/flows", Some(json!({ "kind": "registration" })))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json()["code"], "registration-closed");
    assert_eq!(e.sent().len(), 0);
    let open = env(0xd2, "m48-open", AuthPolicy::DEFAULT).await;
    let mut b = open.browser("m48-open");
    let at = b.register("new@example.com").await;
    assert_eq!(at.status, StatusCode::OK);
}

// OP-159 m.48 (c), m.49 (c)
#[tokio::test]
async fn an_invite_only_environment_without_social_sign_in_offers_no_registration_and_no_provider()
{
    let e = env_full(
        0xd3,
        "m48-mgmt",
        REQUIRED,
        false,
        EnvironmentSignin {
            mfa_required: true,
            registration: Registration::InviteOnly,
            social: false,
            ..EnvironmentSignin::default()
        },
    )
    .await;
    let mut b = e.browser("m48-mgmt");
    let first = b.start().await;
    assert!(node(&first.json(), "provider").is_none());
    let refused = b
        .post("/v1/login/flows", Some(json!({ "kind": "registration" })))
        .await;
    assert_eq!(refused.json()["code"], "registration-closed");
}

// OP-159 m.48 (a), §10.2.2
#[tokio::test]
async fn a_required_second_factor_is_enrolled_in_the_sign_in_and_shows_recovery_codes_once() {
    let e = env(0xd4, "m48-enroll", REQUIRED).await;
    e.account("ada@example.com").await;
    let mut b = e.browser("m48-enroll");
    let step = b.sign_in("ada@example.com").await;
    assert_eq!(
        step.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&step.body)
    );
    assert_eq!(step.step(), "second_factor");
    assert_eq!(step.messages(), vec!["second_factor.enroll"]);
    let body = step.json();
    let setup = node(&body, "totp_setup").unwrap();
    assert!(
        setup["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    assert!(node(&body, "passkey_create").is_some());
    let seed = base32_decode(setup["secret"].as_str().unwrap());
    let again = b.get(&step.action()).await;
    assert_eq!(
        node(&again.json(), "totp_setup").unwrap()["secret"],
        setup["secret"]
    );
    let wrong = b
        .submit(&step, "totp", json!({ "totp_code": "000000" }))
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong.messages(),
        vec!["second_factor.enroll", "second_factor.failed"]
    );
    e.advance(30_000);
    let code = e.totp(&seed);
    let done = b.submit(&step, "totp", json!({ "totp_code": code })).await;
    assert_eq!(
        done.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    assert_eq!(done.step(), "complete");
    let codes = node(&done.json(), "recovery_codes").unwrap()["codes"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(codes, 10);
    let saved = b
        .post(
            "/v1/account/recovery-codes/acknowledgement",
            Some(json!({})),
        )
        .await;
    assert!(saved.status.is_success(), "{}", saved.status);

    let mut other = e.browser("m48-enroll-2");
    let next = other.sign_in("ada@example.com").await;
    assert_eq!(next.step(), "second_factor");
    assert!(node(&next.json(), "totp_setup").is_none());
    let refused = other
        .submit(&next, "totp", json!({ "totp_code": e.totp(&seed) }))
        .await;
    assert_ne!(refused.json()["step"], "complete");
}
