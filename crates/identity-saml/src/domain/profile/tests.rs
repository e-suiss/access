#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;
use crate::sp::{Binding, Endpoint};

fn sp(template: &str) -> Sp {
    Sp::from_json(&serde_json::json!({
        "entity_id": "https://sp.test/metadata",
        "template": template,
        "acs": [{ "url": "https://sp.test/acs", "index": 0, "binding": "post" }],
    }))
    .unwrap()
}

fn with_attrs(mut s: Sp, names: &[&str]) -> Sp {
    s.attributes = names
        .iter()
        .map(|n| crate::sp::Attribute {
            name: String::from(*n),
            name_format: None,
            friendly_name: None,
            source: Some(crate::sp::Source::Email),
            values: vec![],
        })
        .collect();
    s
}

// IDP-28, IDP-40, OP-155 m.3 (q)
#[test]
fn every_shipped_profile_loads() {
    for (t, source) in SHIPPED {
        let p = Profile::load(source).unwrap();
        assert_eq!(p.template.as_deref(), Some(t));
        assert!(p.name.starts_with("saml."));
        assert_ne!(p.tolerances.len(), 0);
        assert!(
            p.tolerances
                .iter()
                .all(|(_, test)| test.starts_with("identity_saml::domain::profile::tests::"))
        );
    }
}

// §10.6.1
#[test]
fn aws_requires_role_and_session_name() {
    let p = Profile::shipped("aws-iam").unwrap();
    assert_eq!(p.apply(sp("aws-iam")), Err(SpError::Profile));
    let ok = with_attrs(
        sp("aws-iam"),
        &[
            "https://aws.amazon.com/SAML/Attributes/Role",
            "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
        ],
    );
    assert!(p.apply(ok.clone()).is_ok());
    let wrong_case = with_attrs(
        sp("aws-iam"),
        &[
            "https://aws.amazon.com/SAML/Attributes/role",
            "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
        ],
    );
    assert_eq!(p.apply(wrong_case), Err(SpError::Profile));
}

// IDP-15
#[test]
fn idp_initiated_stays_opt_in_per_registration() {
    let s = with_attrs(
        sp("aws"),
        &[
            "https://aws.amazon.com/SAML/Attributes/Role",
            "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
        ],
    );
    let applied = Profile::shipped("aws").unwrap().apply(s).unwrap();
    assert!(!applied.allow_idp_initiated);
}

// §10.6.1
#[test]
fn identity_center_takes_email_and_no_encryption() {
    let p = Profile::shipped("aws-identity-center").unwrap();
    let applied = p.apply(sp("aws-identity-center")).unwrap();
    assert_eq!(applied.nameid_format, NameIdFormat::Email);
    let mut enc = sp("aws-identity-center");
    enc.encrypt_assertion = true;
    enc.encryption_certificate = Some(String::from("MAA="));
    assert_eq!(p.apply(enc), Err(SpError::Profile));
}

// §10.6.1
#[test]
fn entra_takes_persistent_and_idp_email() {
    let p = Profile::shipped("entra").unwrap();
    assert_eq!(p.apply(sp("entra")), Err(SpError::Profile));
    let applied = p.apply(with_attrs(sp("entra"), &["IDPEmail"])).unwrap();
    assert_eq!(applied.nameid_format, NameIdFormat::Persistent);
    assert_eq!(applied.attribute_name_format, NameFormat::Unspecified);
}

// §10.6.1
#[test]
fn salesforce_requires_the_assertion_signature_and_its_audience() {
    let p = Profile::shipped("salesforce").unwrap();
    let applied = p.apply(sp("salesforce")).unwrap();
    assert_eq!(applied.audience(), "https://saml.salesforce.com");
    let mut unsigned = sp("salesforce");
    unsigned.sign_assertion = false;
    assert_eq!(p.apply(unsigned), Err(SpError::Profile));
}

// §10.6.1
#[test]
fn slack_requires_the_response_signature_and_no_logout() {
    let p = Profile::shipped("slack").unwrap();
    let mut s = with_attrs(sp("slack"), &["User.Email"]);
    let applied = p.apply(s.clone()).unwrap();
    assert_eq!(applied.nameid_format, NameIdFormat::Persistent);
    s.sign_response = false;
    assert_eq!(p.apply(s.clone()), Err(SpError::Profile));
    s.sign_response = true;
    s.slo = vec![Endpoint {
        url: String::from("https://sp.test/slo"),
        binding: Binding::Redirect,
    }];
    assert_eq!(p.apply(s), Err(SpError::Profile));
}

// §10.6.1
#[test]
fn atlassian_requires_the_assertion_signature_and_email() {
    let applied = Profile::shipped("atlassian")
        .unwrap()
        .apply(sp("atlassian"))
        .unwrap();
    assert_eq!(applied.nameid_format, NameIdFormat::Email);
    assert!(applied.sign_assertion);
}

fn doc(rule: &str, value: &str) -> String {
    format!(
        "v = 1\nprofile = \"saml.evil\"\nprotocol = \"saml\"\ncounterpart = \"Evil\"\nrevision = 1\n\n[[tolerances]]\nrule = \"{rule}\"\nvalue = {value}\ntest = \"identity_saml::profile::tests::x\"\n"
    )
}

// IDP-40 (5), Ek B 4935
#[test]
fn a_profile_that_relaxes_security_is_refused_at_load() {
    for rule in [
        "saml.verify_signature",
        "saml.accept_unsigned",
        "saml.clock_skew",
        "saml.not_on_or_after",
        "saml.audience_check",
        "saml.recipient_check",
        "saml.parser_isolation",
        "saml.max_depth",
    ] {
        assert_eq!(
            Profile::load(&doc(rule, "false")),
            Err(ProfileError::Unknown(String::from(rule))),
            "{rule}"
        );
    }
    assert_eq!(
        Profile::load(&doc("saml.signature_alg", "\"rsa-sha1\"")),
        Err(ProfileError::Relaxes(String::from("saml.signature_alg")))
    );
    assert_eq!(
        Profile::load(&doc("saml.sign_response", "false")),
        Err(ProfileError::Relaxes(String::from("saml.sign_response")))
    );
    assert!(Profile::load(&doc("saml.sign_response", "true")).is_ok());
    let mixed = format!(
        "{}\n[[tolerances]]\nrule = \"saml.clock_skew\"\nvalue = 3600\ntest = \"a::b\"\n",
        doc("saml.sign_response", "true")
    );
    assert!(matches!(
        Profile::load(&mixed),
        Err(ProfileError::Unknown(_))
    ));
    assert!(matches!(
        Profile::load(&doc("scim.no_etag", "true")),
        Err(ProfileError::Unknown(_))
    ));
}
