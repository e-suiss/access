use access_store::idp::ClientRow;

use super::*;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn client() -> Client {
    Client::from_row(ClientRow {
        client_uuid: [1; 16],
        client_id: String::from("cli_x"),
        display_name: String::from("Shop"),
        auth_method: String::from("none"),
        jwks_uri: None,
        redirect_uris: vec![String::from("https://shop.example/cb")],
        active: true,
        secret_hash: None,
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        jwks: None,
        platform_product: None,
        service_key: None,
        event_receiver: None,
    })
    .unwrap()
}

fn issuer() -> Issuer {
    Issuer::parse("https://acme.id.test").unwrap()
}

fn params(extra: &[(&str, &str)]) -> Params {
    let mut p = vec![
        ("client_id", "cli_x"),
        ("redirect_uri", "https://shop.example/cb"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("state", "s1"),
    ];
    for (k, v) in extra {
        p.retain(|(n, _)| n != k);
        if !v.is_empty() {
            p.push((k, v));
        }
    }
    Params::new(p.into_iter().map(|(k, v)| (k.into(), v.into())).collect()).unwrap()
}

fn run(extra: &[(&str, &str)]) -> Result<AuthRequest, AuthError> {
    let p = params(extra);
    let c = client();
    let r = stage_one(&p, Some(&c)).unwrap();
    stage_two(&p, &c, r, &issuer())
}

// IDP-7, TN-34, TN-101, §10.4.1, RFC 9700: code flow with S256 only; implicit, hybrid and
// plain PKCE are refused
#[test]
fn only_the_code_flow_with_s256_is_accepted() {
    let r = run(&[]).unwrap();
    assert!(r.openid());
    assert_eq!(r.state.as_deref(), Some("s1"));
    for rt in ["token", "id_token", "code id_token", "code token"] {
        assert_eq!(
            run(&[("response_type", rt)]).unwrap_err().error,
            "unsupported_response_type"
        );
    }
    assert_eq!(
        run(&[("code_challenge_method", "plain")])
            .unwrap_err()
            .error,
        "invalid_request"
    );
    assert_eq!(
        run(&[("code_challenge_method", "")]).unwrap_err().error,
        "invalid_request"
    );
    assert_eq!(
        run(&[("code_challenge", "")]).unwrap_err().error,
        "invalid_request"
    );
    assert_eq!(
        run(&[("code_challenge", "short")]).unwrap_err().error,
        "invalid_request"
    );
    assert_eq!(
        run(&[("response_mode", "fragment")]).unwrap_err().error,
        "invalid_request"
    );
    assert_eq!(
        run(&[("request", "x.y.z")]).unwrap_err().error,
        "request_not_supported"
    );
    assert_eq!(
        run(&[("scope", "openid admin")]).unwrap_err().error,
        "invalid_scope"
    );
    assert!(run(&[("scope", "")]).is_ok_and(|r| !r.openid()));
}

// §10.4.6, RFC 9470, RFC 8707, RFC 9449 §10: prompt, max_age, acr_values, resource and dpop_jkt
#[test]
fn oidc_and_extension_parameters() {
    assert_eq!(run(&[("prompt", "none")]).unwrap().prompt, Prompt::None);
    assert_eq!(run(&[("prompt", "login")]).unwrap().prompt, Prompt::Login);
    assert_eq!(run(&[("prompt", "create")]).unwrap().prompt, Prompt::Create);
    assert!(run(&[("prompt", "none login")]).is_err());
    assert!(run(&[("prompt", "select_account")]).is_err());
    assert_eq!(run(&[("max_age", "30")]).unwrap().max_age_s, Some(30));
    assert!(run(&[("max_age", "-1")]).is_err());
    assert_eq!(
        run(&[("resource", "https://api.example")])
            .unwrap_err()
            .error,
        "invalid_target"
    );
    assert!(run(&[("resource", "https://acme.id.test")]).is_ok());
    assert!(run(&[("dpop_jkt", "nope")]).is_err());
    let jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    assert!(run(&[("dpop_jkt", jkt)]).unwrap().dpop_jkt.is_some());
}

// RFC 6749 §4.1.2.1, TN-104, X41: a bad client or redirect URI is never redirected; repeated
// parameters are refused
#[test]
fn bad_client_or_redirect_is_not_redirected() {
    let c = client();
    assert_eq!(stage_one(&params(&[]), None), Err(Unredirectable::Client));
    assert_eq!(
        stage_one(
            &params(&[("redirect_uri", "https://evil.example/cb")]),
            Some(&c)
        ),
        Err(Unredirectable::RedirectUri)
    );
    assert_eq!(
        stage_one(&params(&[("redirect_uri", "")]), Some(&c)),
        Err(Unredirectable::RedirectUri)
    );
    assert_eq!(
        Params::parse("client_id=a&client_id=b"),
        Err(Unredirectable::Malformed)
    );
    assert_eq!(Params::parse("a=%zz"), Err(Unredirectable::Malformed));
    assert_eq!(Params::parse("a=x+y%2B").unwrap().get("a"), Some("x y+"));
}

// RFC 9207, TN-11, AG-7: every response carries iss, errors included
#[test]
fn responses_carry_iss() {
    let i = issuer();
    assert_eq!(
        code_redirect("https://shop.example/cb", "c0de", Some("s 1"), &i),
        "https://shop.example/cb?code=c0de&state=s+1&iss=https%3A%2F%2Facme.id.test"
    );
    assert_eq!(
        error_redirect(
            "https://shop.example/cb?x=1",
            AuthError::LOGIN_REQUIRED,
            None,
            &i
        ),
        "https://shop.example/cb?x=1&error=login_required&error_description=the+user+is+not+signed+in&iss=https%3A%2F%2Facme.id.test"
    );
}
