//! OP-156 m.3 (p), m.4: the daemon's operations and answer kinds are those of
//! `conformance/cddl/linux-client.cddl`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;

use access_linux_client::contract::{KINDS, OPS};

fn cddl() -> String {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cddl/linux-client.cddl");
    std::fs::read_to_string(p).unwrap()
}

fn quoted_after(text: &str, key: &str) -> Vec<String> {
    text.match_indices(key)
        .filter_map(|(i, _)| {
            let rest = text.get(i.checked_add(key.len())?..)?;
            let rest = rest.trim_start().strip_prefix('"')?;
            Some(rest.split('"').next()?.to_owned())
        })
        .collect()
}

// OP-156 m.3 (p)
#[test]
fn the_socket_contract_is_the_cddl() {
    let text = cddl();
    let mut ops = quoted_after(&text, "op:");
    ops.sort_unstable();
    let mut ours: Vec<_> = OPS.iter().map(|s| (*s).to_owned()).collect();
    ours.sort_unstable();
    assert_eq!(ops, ours);
    let mut kinds = quoted_after(&text, "kind:");
    kinds.sort_unstable();
    let mut ours: Vec<_> = KINDS.iter().map(|s| (*s).to_owned()).collect();
    ours.sort_unstable();
    assert_eq!(kinds, ours);
}

fn examples(name: &str) -> serde_json::Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/cddl/examples")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// OP-156 m.3 (p)
#[test]
fn the_codec_round_trips_the_cddl_examples() {
    use access_linux_module::wire::{Request, Response};
    let mut seen = 0;
    for (file, request) in [
        ("linux-client-request.json", true),
        ("linux-client-response.json", false),
    ] {
        for case in examples(file)["cases"].as_array().unwrap() {
            let Some(hex) = case["cbor"].as_str() else {
                continue;
            };
            let bytes = unhex(hex);
            let again = if request {
                Request::from_cbor(&bytes).unwrap().to_cbor().unwrap()
            } else {
                Response::from_cbor(&bytes).unwrap().to_cbor().unwrap()
            };
            assert_eq!(again, bytes, "{}", case["id"]);
            seen += 1;
        }
    }
    assert!(seen >= 8);
}

// OP-156 m.3 (p)
#[test]
fn the_codec_refuses_what_the_cddl_does_not_admit() {
    use access_linux_module::wire::{Request, Response, WireError};
    use suiss_crypto::dcbor::{Limits, Value, encode};
    let upper = encode(
        &Value::Map(vec![
            (Value::text("op"), Value::text("getpwnam")),
            (Value::text("name"), Value::text("Ayse")),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(Request::from_cbor(&upper), Err(WireError::Shape));
    let unknown = encode(
        &Value::Map(vec![(Value::text("op"), Value::text("setpwent"))]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(Request::from_cbor(&unknown), Err(WireError::Shape));
    let maybe = encode(
        &Value::Map(vec![
            (Value::text("kind"), Value::text("done")),
            (Value::text("outcome"), Value::text("maybe")),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(Response::from_cbor(&maybe), Err(WireError::Shape));
}
