#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use super::*;
use crate::domain::assurance::{Factor, vector};

const ISSUER: &str = "https://acme.suiss.example";
const SESSION: [u8; 16] = [1; 16];

fn passkey() -> AssuranceVector {
    vector(&[Factor::passkey(
        [2; 16],
        true,
        true,
        false,
        1_767_225_000_000,
    )])
}

// OP-149 m.8
#[test]
fn the_session_id_never_appears() {
    let a = AuthContext::of(ISSUER, &SESSION, &passkey(), None, None, None).unwrap();
    let bytes = a.encode().unwrap();
    assert!(!bytes.windows(16).any(|w| w == SESSION));
    assert_eq!(a.session_ref, context_digest(SESSION_LABEL, &SESSION));
    assert_ne!(session_ref(&SESSION), session_ref(&[2; 16]));
}

// OP-149 m.8, SHA-256
#[test]
fn encoding_and_digest_are_deterministic() {
    let content = Content::new("application/work-record+cbor", [9; 32]).unwrap();
    let a = AuthContext::of(
        ISSUER,
        &SESSION,
        &passkey(),
        Some(1_767_225_060_000),
        None,
        Some(content),
    )
    .unwrap();
    let bytes = a.encode().unwrap();
    assert_eq!(
        dcbor::encode(
            &dcbor::decode(&bytes, Limits::CEILING).unwrap(),
            Limits::CEILING
        )
        .unwrap(),
        bytes
    );
    assert_eq!(a.digest().unwrap(), context_digest(DIGEST_LABEL, &bytes));
    let Value::Map(entries) = a.to_value() else {
        panic!()
    };
    let names: Vec<String> = entries
        .iter()
        .filter_map(|(k, _)| match k {
            Value::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    for field in [
        "v",
        "realm",
        "session_ref",
        "aal",
        "assurance_flags",
        "auth_time",
        "step_up_time",
        "ais_digest",
        "content_type",
        "content_digest",
    ] {
        assert!(names.iter().any(|n| n == field), "{field}");
    }
    let bare = AuthContext::of(ISSUER, &SESSION, &passkey(), None, None, None).unwrap();
    assert_ne!(bare.digest().unwrap(), a.digest().unwrap());
}

// OP-149 m.30 (c)
#[test]
fn the_instance_is_carried_when_the_session_has_one() {
    const INSTANCE: [u8; 16] = [3; 16];
    let bare = AuthContext::of(ISSUER, &SESSION, &passkey(), None, None, None).unwrap();
    let bound = AuthContext::of(ISSUER, &SESSION, &passkey(), None, Some(INSTANCE), None).unwrap();
    let member = |a: &AuthContext| {
        let Value::Map(entries) = a.to_value() else {
            panic!()
        };
        entries
            .into_iter()
            .find(|(k, _)| *k == Value::text("instance"))
            .map(|(_, v)| v)
    };
    assert_eq!(member(&bare), None);
    assert_eq!(member(&bound), Some(Value::Bytes(INSTANCE.to_vec())));
    assert_ne!(bare.encode().unwrap(), bound.encode().unwrap());
    assert_ne!(bare.digest().unwrap(), bound.digest().unwrap());
    assert_eq!(
        bound.digest().unwrap(),
        context_digest(DIGEST_LABEL, &bound.encode().unwrap())
    );
    let other = AuthContext::of(ISSUER, &SESSION, &passkey(), None, Some([4; 16]), None).unwrap();
    assert_ne!(other.digest().unwrap(), bound.digest().unwrap());
}

// §10.1.6, OP-149 m.8
#[test]
fn flags_form_a_sorted_set() {
    let f = flags(&passkey());
    assert_eq!(
        f,
        vec!["human_presence", "phishing_resistant", "synced", "uv"]
    );
    let mut sorted = f.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, f);
    assert_eq!(aal_name(passkey().aal), "aal2");
}

// OP-149 m.8
#[test]
fn ais_digest_commits_to_the_whole_vector() {
    let v = passkey();
    let mut later = v.clone();
    later.auth_time_ms += 1;
    let mut eidas = v.clone();
    eidas.loa_eidas = Some(super::super::assurance::LoaEidas::Substantial);
    let d = ais_digest(&v).unwrap();
    assert_ne!(d, ais_digest(&later).unwrap());
    assert_ne!(d, ais_digest(&eidas).unwrap());
}

// OP-149 m.8
#[test]
fn content_types_are_checked() {
    assert!(Content::new("application/json", [0; 32]).is_ok());
    for bad in [
        "",
        "application",
        "Application/json",
        "application/json; charset=utf-8",
        "/json",
        "application/",
    ] {
        assert_eq!(Content::new(bad, [0; 32]), Err(InvalidContent), "{bad}");
    }
    assert!(Content::new(&format!("a/{}", "b".repeat(200)), [0; 32]).is_err());
}
