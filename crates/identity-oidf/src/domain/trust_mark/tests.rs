use super::*;
use crate::build;
use crate::statement::verify_configuration;
use crate::testkit::{Entity, HOUR, LEAF, NOW, TA, j};

const TYPE: &str = "https://ta.example/member";

fn mark(issuer: &Entity, body: &str) -> String {
    issuer.key.sign(TRUST_MARK_TYP, body)
}

fn body(extra: &str) -> String {
    format!(
        r#"{{"iss":"{TA}","sub":"{LEAF}","iat":{}{extra}}}"#,
        NOW / 1000
    )
}

// IDP-20, OP-155 m.3 (j)
#[test]
fn a_trust_mark_names_its_type_and_subject() {
    let ta = Entity::new(TA);
    let keys = ta.key.keys();
    let exp = NOW.saturating_add(HOUR) / 1000;
    let ok = mark(
        &ta,
        &body(&format!(r#","trust_mark_type":"{TYPE}","exp":{exp}"#)),
    );
    let t = verify_trust_mark(&ok, &keys, LEAF, NOW).unwrap();
    assert_eq!(t.trust_mark_type, TYPE);
    assert_eq!(t.exp_ms, Some(exp * 1000));
    assert_eq!(
        verify_trust_mark(&ok, &keys, "https://other.example", NOW),
        Err(OidfError::TrustMark)
    );
    assert_eq!(
        verify_trust_mark(&ok, &keys, LEAF, NOW.saturating_add(2 * HOUR)),
        Err(OidfError::Time)
    );
    let old = mark(&ta, &body(&format!(r#","id":"{TYPE}""#)));
    assert_eq!(
        verify_trust_mark(&old, &keys, LEAF, NOW),
        Err(OidfError::TrustMark)
    );
    let delegated = mark(
        &ta,
        &body(&format!(
            r#","trust_mark_type":"{TYPE}","delegation":"x.y.z""#
        )),
    );
    assert_eq!(
        verify_trust_mark(&delegated, &keys, LEAF, NOW),
        Err(OidfError::Delegation)
    );
    let wrong_typ = ta
        .key
        .sign("JWT", &body(&format!(r#","trust_mark_type":"{TYPE}""#)));
    assert_eq!(
        verify_trust_mark(&wrong_typ, &keys, LEAF, NOW),
        Err(OidfError::Typ)
    );
}

// IDP-20
#[test]
fn only_listed_issuers_of_unowned_types_are_allowed() {
    let ta = Entity::new(TA);
    let issuers = j(&format!(r#"{{"{TYPE}":["{TA}"]}}"#));
    let ec = ta.config_until(
        &[],
        &ta.federation_metadata(),
        &[],
        NOW.saturating_add(HOUR),
        Some(&issuers),
    );
    let anchor = verify_configuration(&ec, TA, NOW).unwrap();
    assert!(issuer_allowed(&anchor, TYPE, TA));
    assert!(!issuer_allowed(&anchor, TYPE, "https://int.example"));
    assert!(!issuer_allowed(&anchor, "https://ta.example/other", TA));
    let mut owned = anchor.clone();
    owned.trust_mark_owners = Some(j(&format!(r#"{{"{TYPE}":{{"sub":"{TA}"}}}}"#)));
    assert!(!issuer_allowed(&owned, TYPE, TA));
}

// OP-155 m.3 (j)
#[test]
fn a_status_is_kept_for_min_exp_and_one_hour() {
    assert_eq!(status_cache_ms(None, NOW), STATUS_CACHE_MAX_MS);
    assert_eq!(
        status_cache_ms(Some(NOW.saturating_add(600_000)), NOW),
        600_000
    );
    assert_eq!(
        status_cache_ms(Some(NOW.saturating_add(5 * HOUR)), NOW),
        STATUS_CACHE_MAX_MS
    );
    assert_eq!(status_cache_ms(Some(NOW.saturating_sub(1)), NOW), 0);
}

// IDP-19
#[test]
fn a_status_answer_is_signed_by_the_issuer() {
    let ta = Entity::new(TA);
    let tm = mark(&ta, &body(&format!(r#","trust_mark_type":"{TYPE}""#)));
    assert!(status_request_body(&tm).starts_with("trust_mark="));
    assert!(!status_request_body("a b").contains(' '));
    let payload = build::status_response(TA, &tm, "active", NOW).unwrap();
    let answer = ta.key.sign(STATUS_TYP, &payload);
    let s = parse_status_response(&answer, TA, &ta.key.keys(), &tm, NOW).unwrap();
    assert!(s.active());
    let revoked = ta.key.sign(
        STATUS_TYP,
        &build::status_response(TA, &tm, "revoked", NOW).unwrap(),
    );
    assert!(
        !parse_status_response(&revoked, TA, &ta.key.keys(), &tm, NOW)
            .unwrap()
            .active()
    );
    assert_eq!(
        parse_status_response(&answer, TA, &ta.key.keys(), "other", NOW),
        Err(OidfError::Claims)
    );
    let stranger = Entity::new(TA);
    assert_eq!(
        parse_status_response(&answer, TA, &stranger.key.keys(), &tm, NOW),
        Err(OidfError::Signature)
    );
}
