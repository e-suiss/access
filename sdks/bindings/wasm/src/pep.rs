//! What a TypeScript PEP needs after `verifyReceipt` (§9.5.2 k.6, L2-RCP-3, OP-141 m.6): that the
//! verified receipt names the Exercise of this request's nonce (or of the Exercise continued),
//! and the position the decision reflects. No CBOR is read in TypeScript (OP-8).

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::meta::exercise_id;
use access_kernel::receipt::Receipt;
use suiss_crypto::dcbor::{self, Limits};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

fn digest_of(b: &[u8]) -> Result<Digest, &'static str> {
    if let Ok(d) = <[u8; 32]>::try_from(b) {
        return Ok(Digest(d));
    }
    let v = dcbor::decode(b, Limits::CEILING).map_err(|_| "input")?;
    Digest::from_value(&v).ok_or("input")
}

/// The position of a verified `receipt` (what `verifyReceipt` returns) when it names the
/// Exercise of `nonce` in `domain`, or `continued` when that is not empty.
///
/// # Errors
/// `input`, or `receipt-exercise` when it names another Exercise.
pub(crate) fn receipt_position(
    receipt: &[u8],
    domain: &[u8],
    nonce: &[u8],
    continued: &[u8],
) -> Result<u64, &'static str> {
    let r = Receipt::from_bytes(receipt).map_err(|_| "input")?;
    let domain = digest_of(domain)?;
    let expected = if continued.is_empty() {
        exercise_id(&domain, nonce).map_err(|_| "input")?
    } else {
        digest_of(continued)?
    };
    if r.exercise != expected || r.domain != domain {
        return Err("receipt-exercise");
    }
    Ok(r.record)
}

/// See [`receipt_position`].
///
/// # Errors
/// `input` or `receipt-exercise`.
#[wasm_bindgen(js_name = receiptPosition)]
pub fn receipt_position_js(
    receipt: &[u8],
    domain: &[u8],
    nonce: &[u8],
    continued: &[u8],
) -> Result<u64, JsError> {
    receipt_position(receipt, domain, nonce, continued).map_err(JsError::new)
}
