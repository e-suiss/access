#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;

use serde_json::{Value as Json, json};

use super::{CborError, cbor_body, json_body};
use crate::adp::domain::{decode, decode_batch};

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/management/1/adp-cbor.json")
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

const MAX: usize = 64 * 1024;

fn digests(route: &str, body: &[u8]) -> Vec<String> {
    let one = |d: &crate::adp::domain::Decoded| {
        hex(&access_kernel::intent::intent_digest(&d.request.intent)
            .unwrap()
            .0)
    };
    if route.ends_with("/evaluations") {
        let (items, _) = decode_batch(body, MAX).unwrap();
        items.iter().map(|i| one(i.as_ref().unwrap())).collect()
    } else {
        vec![one(&decode(body, MAX).unwrap())]
    }
}

// OP-155 m.3 (q), §9.5.1, Ek B 5076
#[test]
fn the_cbor_form_is_the_dcbor_of_the_same_fields() {
    let mut doc: Json = serde_json::from_str(&std::fs::read_to_string(vectors()).unwrap()).unwrap();
    let committed = doc.clone();
    for case in doc["cases"].as_array_mut().unwrap() {
        let body = serde_json::to_vec(&case["json"]).unwrap();
        let route = case["route"].as_str().unwrap().to_owned();
        case["cbor"] = json!(hex(&cbor_body(&body).unwrap()));
        case["intent_digests"] = json!(digests(&route, &body));
    }
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            vectors(),
            format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()),
        )
        .unwrap();
        return;
    }
    assert_eq!(
        committed, doc,
        "vectors are stale; run with ACCESS_UPDATE_VECTORS=1"
    );
    for case in committed["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let route = case["route"].as_str().unwrap();
        let read = json_body(&unhex(case["cbor"].as_str().unwrap())).unwrap();
        assert_eq!(
            serde_json::from_slice::<Json>(&read).unwrap(),
            case["json"],
            "{name}"
        );
        assert_eq!(
            json!(digests(route, &read)),
            case["intent_digests"],
            "{name}"
        );
        let direct = serde_json::to_vec(&case["json"]).unwrap();
        if route.ends_with("/evaluation") {
            assert_eq!(
                format!("{:?}", decode(&read, MAX).unwrap()),
                format!("{:?}", decode(&direct, MAX).unwrap()),
                "{name}"
            );
        }
    }
    for case in committed["rejections"].as_array().unwrap() {
        let got = json_body(&unhex(case["cbor"].as_str().unwrap())).unwrap_err();
        assert_eq!(got.code(), case["error"], "{}", case["name"]);
    }
}

// OP-155 m.3 (q)
#[test]
fn an_answer_drops_null_members_and_refuses_what_dcbor_cannot_hold() {
    let cbor = cbor_body(br#"{"b": null, "a": [1, -2, true, "x"]}"#).unwrap();
    assert_eq!(
        serde_json::from_slice::<Json>(&json_body(&cbor).unwrap()).unwrap(),
        json!({ "a": [1, -2, true, "x"] })
    );
    assert_eq!(cbor_body(br#"{"a": 1.5}"#), Err(CborError::Unrepresentable));
    assert_eq!(cbor_body(br"[null]"), Err(CborError::Unrepresentable));
}
