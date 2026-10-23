//! Bench inputs taken from the conformance vectors, so benches measure what the tests check.

use access_kernel::codec::Canonical;
use access_kernel::combinator::codec::OwnedInput;
use access_kernel::model::CanonicalAuthority;

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

fn cases(json: &str) -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.get("cases").and_then(|c| c.as_array()).cloned())
        .unwrap_or_default()
}

fn field(cases: &[serde_json::Value], id: &str, key: &str) -> Vec<u8> {
    cases
        .iter()
        .find(|c| c.get("id").and_then(|v| v.as_str()) == Some(id))
        .and_then(|c| c.get(key).and_then(|v| v.as_str()))
        .map(hex)
        .unwrap_or_default()
}

pub(crate) fn authority_bytes() -> Vec<u8> {
    field(
        &cases(include_str!(
            "../../../../conformance/vectors/core/1/codec.json"
        )),
        "canonical_authority.full",
        "cbor",
    )
}

pub(crate) fn authority() -> Option<CanonicalAuthority> {
    CanonicalAuthority::from_bytes(&authority_bytes()).ok()
}

pub(crate) fn decision_input(id: &str) -> Option<OwnedInput> {
    OwnedInput::from_bytes(&field(
        &cases(include_str!(
            "../../../../conformance/vectors/core/1/decision.json"
        )),
        id,
        "input",
    ))
    .ok()
}

pub(crate) fn ed25519_case() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let c = cases(include_str!(
        "../../../../conformance/vectors/core/1/ed25519-strict.json"
    ));
    (
        field(&c, "speccheck-3", "public_key"),
        field(&c, "speccheck-3", "message"),
        field(&c, "speccheck-3", "signature"),
    )
}
