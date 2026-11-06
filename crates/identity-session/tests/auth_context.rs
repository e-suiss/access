//! The `auth_context` the code builds is byte for byte the committed example of
//! `conformance/cddl/examples/auth-context.json`, which `crates/kernel/tests/contracts.rs`
//! checks against `auth-context.cddl` (OP-149 m.8).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_session::domain::assurance::{Factor, vector};
use access_identity_session::domain::auth_context::{AuthContext, Content};

const T: u64 = 1_767_225_000_000;

fn committed(id: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/cddl/examples/auth-context.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap();
    let hex = case["cbor"].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// OP-149 m.8
#[test]
fn the_code_produces_the_committed_examples() {
    let assurance = vector(&[Factor::passkey([2; 16], true, true, false, T)]);
    let content = Content::new("application/work-record+cbor", [9; 32]).unwrap();
    let full = AuthContext::of(
        "https://acme.suiss.example",
        &[1; 16],
        &assurance,
        Some(T + 60_000),
        None,
        Some(content),
    )
    .unwrap();
    assert_eq!(full.encode().unwrap(), committed("session-with-content"));
    let bare = AuthContext::of(
        "https://acme.suiss.example",
        &[1; 16],
        &assurance,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(bare.encode().unwrap(), committed("session-only"));
    // OP-149 m.30 (c)
    let bound = AuthContext::of(
        "https://acme.suiss.example",
        &[1; 16],
        &assurance,
        None,
        Some([3; 16]),
        None,
    )
    .unwrap();
    assert_eq!(bound.encode().unwrap(), committed("session-with-instance"));
}
