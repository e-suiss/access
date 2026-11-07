#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use serde_json::json;

use super::*;
use crate::domain::realm::{CONSOLE_ABSOLUTE_MAX_MS, CONSOLE_IDLE_MAX_MS};

fn ids() -> IdKey {
    IdKey::new(Secret::new([7; 32]))
}

const CLIENT: &str = "cli_0123456789abcdefghjkmnpqrs";

// TN-110, OP-151 m.2 M1: each write operation compiles into exactly one idp.* change of its own
// action
#[test]
fn each_operation_compiles_into_its_one_change() {
    let ids = ids();
    let account = ids.encode(SUBJECT_PREFIX, [1; 16]).unwrap();
    let cases = [
        (
            Op::CreateClient,
            None,
            json!({"client_id": CLIENT, "display_name": "Shop",
                   "redirect_uris": ["https://shop.example.com/cb"]}),
            "idp.client.register",
        ),
        (
            Op::PutClient,
            Some(CLIENT),
            json!({"display_name": "Shop", "token_endpoint_auth_method": "client_secret_basic"}),
            "idp.client.update",
        ),
        (
            Op::RetireClient,
            Some(CLIENT),
            json!({}),
            "idp.client.retire",
        ),
        (
            Op::RotateClientSecret,
            Some(CLIENT),
            json!({}),
            "idp.client.secret_rotate",
        ),
        (
            Op::PutGroup,
            Some("staff"),
            json!({"display_name": "Staff"}),
            "idp.group.create",
        ),
        (
            Op::RetireGroup,
            Some("staff"),
            json!({}),
            "idp.group.retire",
        ),
        (
            Op::AddGroupMembers,
            Some("staff"),
            json!({"account_ids": [account]}),
            "idp.group.members_add",
        ),
        (
            Op::RemoveGroupMembers,
            Some("staff"),
            json!({"account_ids": [account]}),
            "idp.group.members_remove",
        ),
        (
            Op::SuspendAccount,
            Some(account.as_str()),
            json!({}),
            "idp.account.suspend",
        ),
        (
            Op::ReactivateAccount,
            Some(account.as_str()),
            json!({}),
            "idp.account.reactivate",
        ),
        (
            Op::PutUpstream,
            Some("google"),
            json!({"issuer": "https://accounts.google.com", "client_id": "abc",
                   "client_secret_ref": "secret://vault/google",
                   "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"}),
            "idp.upstream.register",
        ),
        (
            Op::RetireUpstream,
            Some("google"),
            json!({}),
            "idp.upstream.retire",
        ),
        (
            Op::PutSigninPolicy,
            None,
            json!({"methods": ["email", "passkey", "social:google"], "mfa_required": true,
                   "required_fields": ["email"], "domain_deny": ["spam.example"]}),
            "idp.realm.signin_policy",
        ),
        (
            Op::PutSessionPolicy,
            None,
            json!({"absolute_ms": "3600000", "idle_ms": 600_000, "binding": "ip"}),
            "idp.realm.session_policy",
        ),
        (
            Op::PutBranding,
            None,
            json!({"display_name": "Acme"}),
            "idp.realm.branding",
        ),
        (
            Op::PutRpId,
            None,
            json!({"rp_id": "acme.example", "acknowledge_passkey_loss": "0"}),
            "idp.realm.rp_id",
        ),
        (
            Op::PutMapper,
            Some("department"),
            json!({"source": "locale"}),
            "idp.mapper.set",
        ),
    ];
    for (op, key, body, action) in cases {
        let change = compile(op, key, &body, &ids).unwrap_or_else(|e| panic!("{op:?}: {e}"));
        assert_eq!(change.action().label(), action, "{op:?}");
    }
}

// TN-61, TNI-6, CR-38: no body sets a credential; an unknown member, a secret or a password
// is refused, and the platform product fields are read-only (OP-149 m.4)
#[test]
fn no_body_sets_a_credential() {
    let ids = ids();
    for body in [
        json!({"display_name": "Shop", "client_secret": "s3cret"}),
        json!({"display_name": "Shop", "password": "hunter2"}),
        json!({"display_name": "Shop", "platform_product": "work"}),
    ] {
        assert!(
            compile(Op::PutClient, Some(CLIENT), &body, &ids).is_err(),
            "{body}"
        );
    }
    let account = ids.encode(SUBJECT_PREFIX, [1; 16]).unwrap();
    for body in [json!({"password": "x"}), json!({"totp": "x"})] {
        assert_eq!(
            compile(Op::SuspendAccount, Some(&account), &body, &ids),
            Err(Invalid::Body)
        );
    }
    assert_eq!(
        compile(
            Op::PutUpstream,
            Some("google"),
            &json!({"issuer": "https://a.example", "client_id": "c",
                    "client_secret_ref": "hunter2", "jwks_uri": "https://a.example/j"}),
            &ids
        )
        .and_then(
            |c| c.check(&access_identity_oauth::adapters::outbound::DeclaredTargets::default())
        ),
        Err(Invalid::Upstream),
        "a secret is a reference, never the secret"
    );
}

// TN-117: a group's members are issued by the administration or by one upstream provider
#[test]
fn a_group_names_its_one_membership_issuer() {
    let ids = ids();
    let up = compile(
        Op::PutGroup,
        Some("eng"),
        &json!({"display_name": "Eng", "membership_issuer": "upstream:google"}),
        &ids,
    )
    .unwrap();
    let Change::GroupCreate(g) = up else {
        panic!("not a create")
    };
    assert_eq!(
        g.issuer,
        MembershipIssuer::Upstream(Name::parse("google").unwrap())
    );
    for bad in ["both", "upstream:", "upstream:Google", "admin:x"] {
        assert_eq!(
            MembershipIssuer::parse(bad),
            Err(Invalid::MembershipIssuer),
            "{bad}"
        );
    }
}

// TN-129, OP-151 m.3 (f): the console session lives at most 12 h, idles at most 15 min, and is
// always bound; `none` is refused for the management surface
#[test]
fn the_console_session_policy_only_tightens() {
    let ok = SessionPolicy::DEFAULT;
    assert_eq!(ok.check(), Ok(()));
    for bad in [
        SessionPolicy {
            absolute_ms: CONSOLE_ABSOLUTE_MAX_MS + 1,
            ..ok
        },
        SessionPolicy {
            idle_ms: CONSOLE_IDLE_MAX_MS + 1,
            ..ok
        },
        SessionPolicy {
            binding: Binding::None,
            ..ok
        },
        SessionPolicy {
            absolute_ms: 120_000,
            idle_ms: 600_000,
            binding: Binding::Asn,
        },
    ] {
        assert_eq!(bad.check(), Err(Invalid::SessionPolicy), "{bad:?}");
    }
}

// TN-132: methods are from the closed set, at least one; fields from the profile; the domain
// lists are DNS names and disjoint
#[test]
fn sign_in_requirements_are_checked() {
    let mut p = default_signin();
    assert_eq!(p.check(), Ok(()));
    assert_eq!(SigninMethod::parse("sms"), Err(Invalid::SigninPolicy));
    p.domain_allow.insert(String::from("acme.example"));
    p.domain_deny.insert(String::from("acme.example"));
    assert_eq!(p.check(), Err(Invalid::SigninPolicy));
    let mut q = default_signin();
    q.required_fields.insert(String::from("password"));
    assert_eq!(q.check(), Err(Invalid::SigninPolicy));
    let mut r = default_signin();
    r.methods.clear();
    assert_eq!(r.check(), Err(Invalid::SigninPolicy));
}

// TN-110, OP-65: a write's intent validity is RFC 3339, ordered and at most 15 minutes
#[test]
fn the_validity_is_bounded() {
    let now = 1_800_000_000_000;
    let body = json!({ "validity": default_validity(now) });
    let w = validity(&body).unwrap();
    assert!(w.from < now && now < w.until);
    for v in [
        json!({"not_before": rfc3339(now), "not_after": rfc3339(now)}),
        json!({"not_before": rfc3339(now), "not_after": rfc3339(now + MAX_VALIDITY_MS + 1)}),
        json!({"not_before": "yesterday", "not_after": rfc3339(now)}),
    ] {
        assert_eq!(
            validity(&json!({ "validity": v })),
            Err(Invalid::Validity),
            "{v}"
        );
    }
    assert_eq!(validity(&json!({})), Err(Invalid::Validity));
}

// CR-38, TN-61: a client's view carries no secret
#[test]
fn a_client_view_has_no_secret() {
    let row = ClientRow {
        client_uuid: [1; 16],
        client_id: String::from(CLIENT),
        display_name: String::from("Shop"),
        auth_method: String::from("client_secret_basic"),
        jwks_uri: None,
        redirect_uris: Vec::new(),
        active: true,
        secret_hash: Some([9; 32]),
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        jwks: None,
        platform_product: None,
        service_key: None,
        event_receiver: None,
        require_par: false,
    };
    let text = client_view(&row).to_string();
    assert!(
        !text.contains("secret_hash") && !text.contains("CQkJ"),
        "{text}"
    );
}
