//! OP-155 m.3 (c), m.6 (h): the committed edge channel examples, which
//! `crates/kernel/tests/contracts.rs` checks against `conformance/cddl/edge-channel.cddl`, are
//! what the served calls' decoders accept, and they encode back to the same bytes.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_internal_api::edge::{
    Audit, Audited, Hello, IssueClaim, Issued, Subject, SubjectLookup, decode_hello_request,
    hello_request,
};
use serde_json::Value;

fn cases(file: &str) -> Vec<(String, Vec<u8>)> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/cddl/examples")
        .join(file);
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["valid"] == true)
        .map(|c| {
            let hex = c["cbor"].as_str().unwrap();
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            (c["id"].as_str().unwrap().to_owned(), bytes)
        })
        .collect()
}

// OP-155 m.3 (c), m.6 (h), IDI-11
#[test]
fn served_request_examples_are_what_the_decoders_read() {
    let mut seen = 0;
    for (id, bytes) in cases("edge-channel-request.json") {
        let back = match id.as_str() {
            "hello" => {
                decode_hello_request(&bytes).unwrap();
                hello_request()
            }
            "subject-lookup" => SubjectLookup::decode(&bytes).unwrap().encode(),
            "issue-claim" | "issue-claim-without-evidence" => {
                IssueClaim::decode(&bytes).unwrap().encode()
            }
            "audit" | "audit-with-subject" => Audit::decode(&bytes).unwrap().encode(),
            other if other.ends_with("-planned") => continue,
            other => panic!("{other} has no decoder"),
        };
        assert_eq!(back, bytes, "{id}");
        seen += 1;
    }
    assert_eq!(seen, 6);
}

// OP-155 m.3 (c), m.6 (h)
#[test]
fn answer_examples_are_what_the_decoders_read() {
    for (id, bytes) in cases("edge-channel-response.json") {
        let back = match id.as_str() {
            "hello" => Hello::decode(&bytes).unwrap().encode(),
            "subject-found" | "subject-none" => Subject::decode(&bytes).unwrap().encode(),
            "queued" => Issued::decode(&bytes).unwrap().encode(),
            "recorded" => Audited::decode(&bytes).unwrap().encode(),
            other => panic!("{other} has no decoder"),
        };
        assert_eq!(back, bytes, "{id}");
    }
}
