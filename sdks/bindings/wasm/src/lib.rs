//! WebAssembly binding of the Access Kernel (OP-8, OP-83, OP-116).
//!
//! Structured values cross as canonical CBOR in a `Uint8Array`, in the shapes of
//! `conformance/cddl/kernel.cddl`; `u64` crosses as `bigint` (OP-8 TS profile). A failure is
//! thrown as a JS `Error` whose `message` is the stable name the conformance vectors use, for
//! example `fuel`, `high-s` or `algorithm not allowed`.

#![forbid(unsafe_code)]

use access_kernel::binding;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

fn js(e: binding::Error) -> JsError {
    JsError::new(&e.name())
}

/// Kernel public API version as `"major.minor"`.
#[wasm_bindgen(js_name = apiVersion)]
#[must_use]
pub fn api_version() -> String {
    binding::api_version()
}

/// `evaluation-input` and fuel to `decision` (OP-111, OP-116 m.5).
///
/// # Errors
/// `input` or `fuel`.
#[wasm_bindgen]
pub fn evaluate(input: &[u8], fuel: u64) -> Result<Vec<u8>, JsError> {
    binding::evaluate(input, fuel).map_err(js)
}

/// Child ⊆ Parent for a holder under a catalog (§5.8).
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = childWithinParent)]
pub fn child_within_parent(
    child: &[u8],
    parent: &[u8],
    holder: &[u8],
    catalog: &[u8],
) -> Result<bool, JsError> {
    binding::child_within_parent(child, parent, holder, catalog).map_err(js)
}

/// `intent-envelope` to its `digest`.
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = intentDigest)]
pub fn intent_digest(envelope: &[u8]) -> Result<Vec<u8>, JsError> {
    binding::intent_digest(envelope).map_err(js)
}

/// Tagged `COSE_Sign1` and `key-set` to `{kid, payload}`.
///
/// # Errors
/// `input` or a COSE name.
#[wasm_bindgen(js_name = verifyCoseSign1)]
pub fn verify_cose_sign1(
    sign1: &[u8],
    key_set: &[u8],
    content_type: &str,
) -> Result<Vec<u8>, JsError> {
    binding::verify_cose_sign1(sign1, key_set, content_type).map_err(js)
}

/// Binding-signed Domain Metadata and trusted `key-set` to `domain-metadata`.
///
/// # Errors
/// `input` or a key-scope name.
#[wasm_bindgen(js_name = verifyMetadata)]
pub fn verify_metadata(signed: &[u8], trusted: &[u8]) -> Result<Vec<u8>, JsError> {
    binding::verify_metadata(signed, trusted).map_err(js)
}

/// `domain-metadata`, artefact domain, signed excerpt, usage and `iat` to `operational-key`.
///
/// # Errors
/// `input` or a key-scope name.
#[wasm_bindgen(js_name = operationalKey)]
pub fn operational_key(
    metadata: &[u8],
    domain: &[u8],
    excerpt: &[u8],
    usage: &str,
    iat: u64,
) -> Result<Vec<u8>, JsError> {
    binding::operational_key(metadata, domain, excerpt, usage, iat).map_err(js)
}

/// Access-native compact JWS to its payload JSON text, after the claim checks.
///
/// # Errors
/// `input`, a JWS name or a claim name.
#[wasm_bindgen(js_name = verifyJwsCompact)]
pub fn verify_jws_compact(
    token: &str,
    key_set: &[u8],
    typ: &str,
    issuer: &str,
    audience: &str,
    now: u64,
    skew_ms: u64,
) -> Result<String, JsError> {
    binding::verify_jws_compact(token, key_set, typ, issuer, audience, now, skew_ms).map_err(js)
}

/// Access-native SD-JWT presentation to its disclosed claims JSON text.
///
/// # Errors
/// `input` or an SD-JWT name.
#[wasm_bindgen(js_name = verifySdJwt)]
pub fn verify_sd_jwt(
    presentation: &str,
    key_set: &[u8],
    typ: &str,
    audience: &str,
    nonce: &str,
    now: u64,
    skew_ms: u64,
) -> Result<String, JsError> {
    binding::verify_sd_jwt(presentation, key_set, typ, audience, nonce, now, skew_ms).map_err(js)
}

/// Checks a `validity-contract` at the moment of use (§9.12, OP-118 m.4).
///
/// # Errors
/// `input` or a validity name.
#[allow(clippy::too_many_arguments, reason = "OP-116 m.9")]
#[wasm_bindgen(js_name = checkValidity)]
pub fn check_validity(
    contract: &[u8],
    now: u64,
    audience: &str,
    understood: Vec<String>,
    last_refresh: Option<u64>,
    online: bool,
    skew_ms: u64,
    iat: u64,
    horizon_cap_ms: u64,
) -> Result<(), JsError> {
    binding::check_validity(
        contract,
        now,
        audience,
        understood,
        last_refresh,
        online,
        skew_ms,
        iat,
        horizon_cap_ms,
    )
    .map_err(js)
}

/// RFC 9162 inclusion proof; `path` is the 32-byte hashes concatenated.
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = verifyInclusion)]
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf_hash: &[u8],
    path: &[u8],
    root: &[u8],
) -> Result<bool, JsError> {
    binding::verify_inclusion(index, size, leaf_hash, path, root).map_err(js)
}

/// RFC 9162 consistency proof; `path` is the 32-byte hashes concatenated.
///
/// # Errors
/// `input`.
#[wasm_bindgen(js_name = verifyConsistency)]
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &[u8],
    second_root: &[u8],
    path: &[u8],
) -> Result<bool, JsError> {
    binding::verify_consistency(first, second, first_root, second_root, path).map_err(js)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_kernel_api_version() {
        assert_eq!(api_version(), "0.0");
    }

    #[test]
    fn merkle_proofs_cross_without_throwing() {
        let root = [0_u8; 32];
        assert_eq!(
            verify_consistency(0, 0, &root, &root, &[]).map_err(|_| ()),
            Ok(true)
        );
        assert_eq!(
            verify_inclusion(1, 1, &root, &[], &root).map_err(|_| ()),
            Ok(false)
        );
    }
}
