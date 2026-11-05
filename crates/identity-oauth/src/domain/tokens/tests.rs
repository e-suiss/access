use serde_json::Value;

use super::*;

const NOW: u64 = 1_800_000_000_000;

fn req(prompt: Prompt, max_age_s: Option<u64>, acr: &[&str]) -> AuthRequest {
    AuthRequest {
        client_id: String::from("cli_x"),
        redirect_uri: String::from("https://shop.example/cb"),
        scope: vec![String::from("openid")],
        state: None,
        nonce: None,
        code_challenge: [0; 32],
        prompt,
        max_age_s,
        acr_values: acr.iter().map(|a| String::from(*a)).collect(),
        dpop_jkt: None,
        authority: None,
    }
}

const OLD: Signed = Signed {
    auth_time_ms: NOW - 3_600_000,
    aal: Aal::Aal1,
};

// §10.4.6, RFC 9470, TN-44: prompt=login, max_age and acr_values send the browser to the login
// once; a sign-in after the request satisfies them
#[test]
fn login_is_needed_once_per_request() {
    let created = NOW - 1_000;
    assert_eq!(
        needs_login(&req(Prompt::Default, None, &[]), None, created, NOW),
        Some(LoginReason::SignIn)
    );
    assert_eq!(
        needs_login(&req(Prompt::Create, None, &[]), None, created, NOW),
        Some(LoginReason::Create)
    );
    assert_eq!(
        needs_login(&req(Prompt::Default, None, &[]), Some(OLD), created, NOW),
        None
    );
    assert_eq!(
        needs_login(&req(Prompt::Login, None, &[]), Some(OLD), created, NOW),
        Some(LoginReason::Reauthenticate)
    );
    assert_eq!(
        needs_login(
            &req(Prompt::Default, Some(60), &[]),
            Some(OLD),
            created,
            NOW
        ),
        Some(LoginReason::Reauthenticate)
    );
    assert_eq!(
        needs_login(
            &req(Prompt::Default, Some(7200), &[]),
            Some(OLD),
            created,
            NOW
        ),
        None
    );
    let aal2 = acr(Aal::Aal2);
    assert_eq!(
        needs_login(
            &req(Prompt::Default, None, &[aal2]),
            Some(OLD),
            created,
            NOW
        ),
        Some(LoginReason::StepUp(Aal::Aal2))
    );
    assert_eq!(
        needs_login(
            &req(Prompt::Default, None, &["urn:unknown"]),
            Some(OLD),
            created,
            NOW
        ),
        None
    );
    let fresh = Signed {
        auth_time_ms: created,
        aal: Aal::Aal1,
    };
    for r in [
        req(Prompt::Login, Some(0), &[aal2]),
        req(Prompt::Create, None, &[]),
    ] {
        assert_eq!(needs_login(&r, Some(fresh), created, NOW), None);
    }
}

fn claims(bytes: &[u8]) -> serde_json::Map<String, Value> {
    match serde_json::from_slice(bytes).unwrap() {
        Value::Object(m) => m,
        other => panic!("{other}"),
    }
}

// MD-7, §10.4.5, RFC 9068, TN-27, PI-11, OP-146 m.5 (c), E39: ID token ≤ 5 minutes with one
// audience; the access token names the realm as its single audience, is always cnf-bound and
// carries no authority
#[test]
fn identity_assertions_have_their_profile() {
    let issuer = Issuer::parse("https://acme.id.test").unwrap();
    let f = TokenFacts {
        issuer: &issuer,
        client_id: "cli_x",
        sub: "pw",
        sid: "sid",
        auth_time_ms: NOW - 5_000,
        aal: Aal::Aal2,
        now_ms: NOW,
        rev: 3,
    };
    let id = claims(&id_token_claims(&f, Some("n")));
    assert_eq!(id["aud"], "cli_x");
    assert_eq!(
        id["exp"].as_u64().unwrap() - id["iat"].as_u64().unwrap(),
        300
    );
    assert_eq!(id["nonce"], "n");
    assert_eq!(id["acr"], acr(Aal::Aal2));
    let at = claims(&access_token_claims(&f, "openid", "j", "k"));
    assert_eq!(at["aud"], "https://acme.id.test");
    assert_eq!(at["cnf"]["jkt"], "k");
    // OP-21, CMP-15.2: the session epoch the token was issued under
    assert_eq!((at["rev"].as_i64(), id["rev"].as_i64()), (Some(3), Some(3)));
    assert_eq!(
        at["exp"].as_u64().unwrap() - at["iat"].as_u64().unwrap(),
        600
    );
    assert!(!at.contains_key("authorization_details"));
    let lt = claims(&logout_token_claims(
        &issuer, "cli_x", "pw", "sid", "j", NOW,
    ));
    assert!(lt["events"].get(LOGOUT_EVENT).is_some());
    assert!(!lt.contains_key("nonce"));
}
