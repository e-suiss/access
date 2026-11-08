#![allow(clippy::type_complexity, reason = "test fixtures")]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::vector_rules::{field, golden, hex};

const URI: &str = "https://access.example/status/7";

fn token() -> ListToken {
    ListToken {
        uri: URI.to_string(),
        iat: 1_767_225_600,
        exp: Some(1_767_229_200),
        ttl: Some(300),
        lst: vec![0x78, 0xda, 0x01],
        aggregation_uri: None,
        as_of: 4_096,
    }
}

fn reference(idx: u64) -> StatusRef {
    StatusRef {
        idx,
        uri: URI.to_string(),
    }
}

// L2-STL-1, L2-STL-2: the reference and the list token round-trip; the list holds one bit per
// entry
#[test]
fn reference_and_token_round_trip() {
    let r = reference(12);
    assert_eq!(StatusRef::from_value(&r.to_value()), Ok(r));
    let t = token();
    assert_eq!(ListToken::from_bytes(&t.to_bytes().unwrap()), Ok(t));
    let two_bits = Value::Map(vec![
        (Value::Unsigned(2), Value::text(URI)),
        (Value::Unsigned(6), Value::Unsigned(1)),
        (
            Value::Unsigned(65_533),
            Value::Map(vec![
                (Value::text("bits"), Value::Unsigned(2)),
                (Value::text("lst"), Value::Bytes(vec![1])),
            ]),
        ),
        (Value::text("as_of"), Value::Unsigned(1)),
    ]);
    let bytes = dcbor::encode(&two_bits, Limits::CEILING).unwrap();
    assert_eq!(ListToken::from_bytes(&bytes), Err(StatusError::Malformed));
}

fn uri_of(len: usize) -> String {
    "u".repeat(len)
}

// L2-STL-1: a reference names a list by a non-empty URI of at most 2048 bytes
#[test]
fn a_reference_uri_is_non_empty_and_bounded() {
    let at = |uri: String| StatusRef::from_value(&StatusRef { idx: 1, uri }.to_value());
    assert_eq!(at(String::new()), Err(ModelError::Range));
    assert!(at(uri_of(1)).is_ok());
    assert!(at(uri_of(MAX_URI)).is_ok());
    assert_eq!(at(uri_of(MAX_URI + 1)), Err(ModelError::Range));
}

fn token_with(uri: String) -> Result<ListToken, StatusError> {
    let v = Value::Map(vec![
        (Value::Unsigned(2), Value::Text(uri)),
        (Value::Unsigned(6), Value::Unsigned(1)),
        (
            Value::Unsigned(65_533),
            Value::Map(vec![
                (Value::text("bits"), Value::Unsigned(1)),
                (Value::text("lst"), Value::Bytes(vec![1])),
            ]),
        ),
        (Value::text("as_of"), Value::Unsigned(1)),
    ]);
    ListToken::from_bytes(&dcbor::encode(&v, Limits::CEILING).unwrap())
}

// L2-STL-2: the list token's subject is a non-empty URI of at most 2048 bytes
#[test]
fn a_list_token_subject_is_non_empty_and_bounded() {
    assert_eq!(token_with(String::new()), Err(StatusError::Malformed));
    assert_eq!(token_with(uri_of(1)).map(|t| t.uri), Ok(uri_of(1)));
    assert_eq!(
        token_with(uri_of(MAX_URI)).map(|t| t.uri.len()),
        Ok(MAX_URI)
    );
    assert_eq!(token_with(uri_of(MAX_URI + 1)), Err(StatusError::Malformed));
}

// L2-STL-2: a text claim other than `as_of` is not part of a list token
#[test]
fn a_list_token_rejects_an_unknown_text_claim() {
    let mut v = token().to_value();
    if let Value::Map(m) = &mut v {
        m.push((Value::text("as_at"), Value::Unsigned(1)));
    }
    let bytes = dcbor::encode(&v, Limits::CEILING).unwrap();
    assert_eq!(ListToken::from_bytes(&bytes), Err(StatusError::Malformed));
}

// L2-STL-3: an unset bit reads as valid even when every lower bit of its byte is set
#[test]
fn an_unset_bit_above_set_bits_is_valid() {
    assert_eq!(is_set(&[0b0000_0111], 3), Ok(false));
    assert_eq!(is_set(&[0b0111_1111], 7), Ok(false));
    assert_eq!(is_set(&[0b1111_1111], 7), Ok(true));
}

fn cases() -> Vec<(
    &'static str,
    &'static [&'static str],
    Vec<u8>,
    Vec<u8>,
    StatusRef,
)> {
    let list = vec![0b0000_0100, 0b1000_0000];
    let ok = token().to_bytes().unwrap();
    let mut without_as_of = token().to_value();
    if let Value::Map(m) = &mut without_as_of {
        m.retain(|(k, _)| *k != Value::text("as_of"));
    }
    let without_as_of = dcbor::encode(&without_as_of, Limits::CEILING).unwrap();
    let other = ListToken {
        uri: "https://access.example/status/8".to_string(),
        ..token()
    }
    .to_bytes()
    .unwrap();
    vec![
        (
            "valid-entry",
            &["L2-STL-3"],
            ok.clone(),
            list.clone(),
            reference(0),
        ),
        (
            "revoked-entry",
            &["L2-STL-3"],
            ok.clone(),
            list.clone(),
            reference(2),
        ),
        (
            "last-bit",
            &["L2-STL-3"],
            ok.clone(),
            list.clone(),
            reference(15),
        ),
        (
            "past-the-end",
            &["L2-STL-3"],
            ok,
            list.clone(),
            reference(16),
        ),
        (
            "another-list",
            &["L2-STL-3"],
            other,
            list.clone(),
            reference(2),
        ),
        (
            "no-position",
            &["L2-STL-2"],
            without_as_of,
            list,
            reference(2),
        ),
    ]
}

fn run(token: &[u8], list: &[u8], r: &StatusRef) -> Result<bool, StatusError> {
    lookup(&ListToken::from_bytes(token)?, list, r)
}

// L2-STL-2, L2-STL-3: the bit at idx mod 8 of byte idx div 8 is read, least significant first,
// only from the referenced list
#[test]
fn lookups_read_the_referenced_bit() {
    let got: Vec<Result<bool, &str>> = cases()
        .iter()
        .map(|(_, _, t, l, r)| run(t, l, r).map_err(StatusError::code))
        .collect();
    assert_eq!(
        got,
        [
            Ok(false),
            Ok(true),
            Ok(true),
            Err("status-index"),
            Err("status-uri"),
            Err("status-malformed"),
        ]
    );
}

// L2-STL-2, L2-STL-3
#[test]
fn status_list_vectors_match() {
    let rows: Vec<String> = cases()
        .iter()
        .map(|(id, rules, t, l, r)| {
            let out = match run(t, l, r) {
                Ok(set) => format!("\"invalid\": {set}"),
                Err(e) => format!("\"error\": \"{}\"", e.code()),
            };
            format!(
                "  {{\"id\": \"{id}\", {}, \"token\": \"{}\", \"list\": \"{}\", \"reference\": \"{}\", {out}}}",
                field(rules),
                hex(t),
                hex(l),
                hex(&r.to_bytes().unwrap())
            )
        })
        .collect();
    let json = format!(
        "{{\n \"rule\": \"L2-STL-3\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"status.lookup\",\n \"cases\": [\n{}\n ]\n}}\n",
        rows.join(",\n")
    );
    golden(
        "status-list.json",
        include_str!("../../../../conformance/vectors/core/1/status-list.json"),
        &json,
    );
}
