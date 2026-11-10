#![allow(clippy::unwrap_used, reason = "test code")]

use access_identity_saml::time::format;

use super::*;

const NOW: u64 = 1_800_000_000_000;

fn facts() -> AssertionFacts {
    AssertionFacts {
        id: String::from("a1"),
        issuer: String::from("https://idp.example"),
        issue_instant: format(NOW),
        name_id: String::from("emp-1"),
        name_id_format: Some(String::from(PERSISTENT)),
        audiences: vec![String::from("https://sp.example/md")],
        not_before: Some(format(NOW - 60_000)),
        not_on_or_after: Some(format(NOW + 300_000)),
        recipient: Some(String::from("https://sp.example/acs")),
        confirmation_not_on_or_after: Some(format(NOW + 300_000)),
        in_response_to: Some(String::from("_req")),
        authn_instant: Some(format(NOW)),
        session_index: Some(String::from("s1")),
        authn_context: Some(String::from("urn:x:mfa")),
        attributes: Vec::new(),
        signed: String::from("rsa-sha256"),
        in_response: true,
    }
}

fn expect() -> Expect<'static> {
    Expect {
        idp: "https://idp.example",
        audience: "https://sp.example/md",
        recipient: Some("https://sp.example/acs"),
        in_response_to: Some("_req"),
        allow_unsolicited: false,
        now_ms: NOW,
    }
}

// §10.6.1, OP-155 m.3 (h)
#[test]
fn a_matching_assertion_gives_its_declarations() {
    let d = check(&facts(), &expect()).unwrap();
    assert_eq!(d.acr.as_deref(), Some("urn:x:mfa"));
    assert_eq!(d.auth_time_ms, Some(NOW));
}

// §10.6.1, OP-155 m.3 (e), (h)
#[test]
fn issuer_audience_recipient_and_time_are_checked() {
    let mut f = facts();
    f.issuer = String::from("https://evil.example");
    assert_eq!(check(&f, &expect()), Err(SamlCheck::Issuer));
    let mut f = facts();
    f.audiences = vec![String::from("https://other.example")];
    assert_eq!(check(&f, &expect()), Err(SamlCheck::Audience));
    let mut f = facts();
    f.recipient = Some(String::from("https://evil.example/acs"));
    assert_eq!(check(&f, &expect()), Err(SamlCheck::Audience));
    let mut e = expect();
    e.now_ms = NOW + 300_000 + SKEW_MS;
    assert_eq!(check(&facts(), &e), Err(SamlCheck::Time));
    let mut f = facts();
    f.not_on_or_after = None;
    f.confirmation_not_on_or_after = None;
    assert_eq!(check(&f, &expect()), Err(SamlCheck::Time));
}

// §10.6.1, §10.2.6, OP-155 m.3 (h), Ek B 4682
#[test]
fn an_unsolicited_response_is_refused_unless_the_connection_opens_it() {
    let mut f = facts();
    f.in_response_to = None;
    let mut e = expect();
    e.in_response_to = None;
    assert_eq!(check(&f, &e), Err(SamlCheck::Unsolicited));
    e.allow_unsolicited = true;
    assert!(check(&f, &e).is_ok());
    e.now_ms = NOW + IDP_INITIATED_MS;
    assert_eq!(
        check(&f, &e),
        Err(SamlCheck::Unsolicited),
        "only while fresh"
    );
    let mut other = facts();
    other.in_response_to = Some(String::from("_someone-else"));
    assert_eq!(check(&other, &expect()), Err(SamlCheck::Unsolicited));
}

// OP-155 m.3 (h)
#[test]
fn the_authn_request_and_metadata_are_canonical_and_ask_for_signed_persistent_subjects() {
    let sp = Sp {
        entity_id: "https://sp.example/md",
        acs: "https://sp.example/acs",
    };
    let r = authn_request(
        &sp,
        "_r1",
        "2026-11-10T10:00:00Z",
        "https://idp.example/sso",
    );
    assert!(r.starts_with("<samlp:AuthnRequest xmlns:samlp="));
    assert!(r.contains(r#"AssertionConsumerServiceURL="https://sp.example/acs""#));
    assert!(r.contains(PERSISTENT));
    let m = metadata(&sp);
    assert!(m.contains(r#"WantAssertionsSigned="true""#));
    assert!(m.contains(r#"AuthnRequestsSigned="true""#));
}
