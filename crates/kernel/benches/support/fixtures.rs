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

/// Reads one case's hex field by scanning the text, without building a JSON tree: the freed
/// nodes of a parsed tree change glibc's heap state and so the instruction count of the first
/// allocations a bench makes (OP-72).
fn field(json: &str, id: &str, key: &str) -> Vec<u8> {
    let case = format!("\"id\": \"{id}\"");
    let key = format!("\"{key}\": \"");
    let Some((_, rest)) = json.split_once(&case) else {
        return Vec::new();
    };
    let rest = rest.split_once("\"id\": \"").map_or(rest, |(r, _)| r);
    rest.split_once(&key)
        .and_then(|(_, v)| v.split_once('"'))
        .map(|(v, _)| hex(v))
        .unwrap_or_default()
}

pub(crate) fn authority_bytes() -> Vec<u8> {
    field(
        include_str!("../../../../conformance/vectors/core/1/codec.json"),
        "canonical_authority.full",
        "cbor",
    )
}

pub(crate) fn authority() -> Option<CanonicalAuthority> {
    CanonicalAuthority::from_bytes(&authority_bytes()).ok()
}

pub(crate) fn decision_input(id: &str) -> Option<OwnedInput> {
    OwnedInput::from_bytes(&field(
        include_str!("../../../../conformance/vectors/core/1/decision.json"),
        id,
        "input",
    ))
    .ok()
}

pub(crate) fn ed25519_case() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let c = include_str!("../../../../conformance/vectors/core/1/ed25519-strict.json");
    (
        field(c, "speccheck-3", "public_key"),
        field(c, "speccheck-3", "message"),
        field(c, "speccheck-3", "signature"),
    )
}
