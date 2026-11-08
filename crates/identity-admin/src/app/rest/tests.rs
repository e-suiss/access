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

// TN-110, OP-151 m.2 M1
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
            Op::LinkUpstreamSubject,
            Some("google"),
            json!({"sub": "1180", "account_id": account}),
            "idp.upstream.link",
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

// TN-61, TNI-6, CR-38
// OP-149
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

// TN-117
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

// TN-129, OP-151 m.3 (f)
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

// TN-132
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

// TN-110, OP-65
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

// CR-38, TN-61
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
        public_sub: false,
        sector_identifier_uri: None,
        third_party: false,
    };
    let text = client_view(&row).to_string();
    assert!(
        !text.contains("secret_hash") && !text.contains("CQkJ"),
        "{text}"
    );
}

// MD-10
#[test]
fn public_sub_needs_the_explicit_opt_in() {
    let ids = ids();
    let body = |extra: Json| {
        let mut b = json!({"client_id": CLIENT, "display_name": "Shop",
                           "redirect_uris": ["https://shop.example/cb"]});
        if let (Some(o), Json::Object(e)) = (b.as_object_mut(), extra) {
            o.extend(e);
        }
        b
    };
    let subject = |extra| match compile(Op::CreateClient, None, &body(extra), &ids) {
        Ok(Change::ClientRegister(c)) => Ok(c.subject),
        Ok(other) => panic!("{other:?}"),
        Err(e) => Err(e),
    };
    assert!(!subject(json!({})).unwrap().public);
    assert_eq!(
        subject(json!({"subject_type": "public"})),
        Err(Invalid::PublicSub)
    );
    assert_eq!(
        subject(json!({"public_sub_opt_in": true})),
        Err(Invalid::PublicSub)
    );
    assert_eq!(
        subject(json!({"subject_type": "global"})),
        Err(Invalid::PublicSub)
    );
    let public = subject(json!({"subject_type": "public", "public_sub_opt_in": true,
                                "sector_identifier_uri": "https://shop.example/sector.json"}))
    .unwrap();
    assert!(public.public);
    assert_eq!(
        public.sector_identifier_uri.as_deref(),
        Some("https://shop.example/sector.json")
    );
}

// MD-10, OIDC §8.1
#[test]
fn a_sector_document_lists_every_redirect_uri() {
    use crate::domain::{RedirectUri, sector_covers};
    let uris = [
        RedirectUri::parse("https://a.example/cb").unwrap(),
        RedirectUri::parse("https://b.example/cb").unwrap(),
    ];
    let doc = br#"["https://a.example/cb","https://b.example/cb","https://c.example/cb"]"#;
    assert_eq!(sector_covers(doc, &uris), Ok(()));
    assert_eq!(
        sector_covers(br#"["https://a.example/cb"]"#, &uris),
        Err(Invalid::SectorIdentifier)
    );
    assert_eq!(
        sector_covers(br#"["https://a.example/cb","http://b.example/cb"]"#, &uris),
        Err(Invalid::SectorIdentifier)
    );
    assert_eq!(
        sector_covers(br#"{"redirect_uris":[]}"#, &uris),
        Err(Invalid::SectorIdentifier)
    );
}

// MUST-NEVER-17, TN-61, TNI-6
#[test]
fn an_administrator_never_sets_a_users_credential() {
    use access_internal_api::idp::IdpAction;
    let account: Vec<_> = IdpAction::ALL
        .into_iter()
        .filter(|a| a.namespace() == "idp.account")
        .collect();
    assert_eq!(
        account,
        [
            IdpAction::AccountDelete,
            IdpAction::AccountSuspend,
            IdpAction::AccountReactivate,
            IdpAction::AccountCanary,
            IdpAction::AccountResetIntent,
            IdpAction::AccountTapIssue,
            IdpAction::AccountRecoveryPolicy,
            IdpAction::AccountRecoveryPolicyLoosen,
            IdpAction::AccountExport,
            IdpAction::AccountMigrationExport,
            IdpAction::AccountRead,
            IdpAction::AccountProfileUpdate,
            IdpAction::AccountEmailChange,
        ]
    );
    for a in IdpAction::ALL {
        let label = a.label().to_lowercase();
        for banned in ["credential", "password", "passkey", "totp", "set_secret"] {
            assert!(!label.contains(banned), "{label}");
        }
    }
    let ids = ids();
    let subject = ids.encode(SUBJECT_PREFIX, [1; 16]).unwrap();
    let chosen = [
        json!({"password": "hunter2"}),
        json!({"credential": {"type": "password", "value": "hunter2"}}),
        json!({"passkey": {"public_key": "pQECAyYgASFYIA"}}),
        json!({"totp_secret": "JBSWY3DPEHPK3PXP"}),
    ];
    for op in [Op::SuspendAccount, Op::ReactivateAccount, Op::MarkCanary] {
        for body in &chosen {
            assert_eq!(
                compile(op, Some(&subject), body, &ids),
                Err(Invalid::Body),
                "{op:?} {body}"
            );
        }
    }
    // TN-61, TN-62, HL-38
    for body in &chosen {
        for op in [Op::ResetIntent, Op::IssueTap] {
            assert_eq!(
                compile(op, Some(&subject), body, &ids),
                Err(Invalid::Body),
                "{op:?} {body}"
            );
        }
    }
    assert_eq!(
        compile(Op::ResetIntent, Some(&subject), &json!({}), &ids),
        Ok(Change::AccountResetIntent {
            subject: [1; 16],
            ttl_ms: 3_600_000,
        })
    );
    assert_eq!(
        compile(
            Op::ResetIntent,
            Some(&subject),
            &json!({"ttl_s": 90_000}),
            &ids
        )
        .unwrap()
        .check(&access_identity_oauth::adapters::outbound::DeclaredTargets::default()),
        Err(Invalid::Body),
        "an intent lives at most 24 hours"
    );
    for name in [
        "setCredential",
        "setPassword",
        "putCredential",
        "createCredential",
    ] {
        assert_eq!(Op::from_operation(name), None, "{name}");
    }
}
