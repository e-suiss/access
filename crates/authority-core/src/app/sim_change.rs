//! SIM change signals (OP-156 m.3 (f), IDP-9, §10.3.4): an operator's or aggregator's
//! `sim_change` Claim names the last SIM change of the subject's line. Its `value` is the body
//! digest of `{last_change_at, checked_at}` (L2-CLB-1, `product-seam.cddl`); Access keeps a
//! disclosed body that matches it, and the identity plane refuses a SIM-based step on a line
//! that changed in the last 90 days. A signal only narrows; it never grants (CI-2, E38).

use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::model::EqValue;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

/// The Claim class.
pub const CLASS: &str = "sim_change";

/// The `sim-change` body (CDDL `product-seam.cddl`).
#[must_use]
pub fn body(last_change_at: u64, checked_at: u64) -> Value {
    Value::Map(vec![
        (Value::text("checked_at"), Value::Unsigned(checked_at)),
        (
            Value::text("last_change_at"),
            Value::Unsigned(last_change_at),
        ),
    ])
}

/// The `value` of a `sim_change` Claim with `body(last_change_at, checked_at)` (L2-CLB-1).
#[must_use]
pub fn value_digest(last_change_at: u64, checked_at: u64) -> [u8; 32] {
    let bytes = dcbor::encode(
        &Value::Array(vec![Value::text(CLASS), body(last_change_at, checked_at)]),
        Limits::CEILING,
    )
    .unwrap_or_default();
    context_digest(BODY_CONTEXT, &bytes).0
}

/// The `(last_change_at, checked_at)` a disclosed body says, when it is the CDDL shape, the check
/// is not before the change and the digest matches `value`.
#[must_use]
pub fn decode(value: Option<&EqValue>, body_bytes: &[u8]) -> Option<(u64, u64)> {
    let Value::Map(entries) = dcbor::decode(body_bytes, Limits::CEILING).ok()? else {
        return None;
    };
    if entries.len() != 2 {
        return None;
    }
    let mut last = None;
    let mut checked = None;
    for (k, v) in &entries {
        match (k, v) {
            (Value::Text(k), Value::Unsigned(n)) if k == "last_change_at" => last = Some(*n),
            (Value::Text(k), Value::Unsigned(n)) if k == "checked_at" => checked = Some(*n),
            _ => return None,
        }
    }
    let (last, checked) = (last?, checked?);
    if checked < last {
        return None;
    }
    match value {
        Some(EqValue::Bytes(d)) if d.as_slice() == value_digest(last, checked) => {
            Some((last, checked))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(v: &Value) -> Vec<u8> {
        dcbor::encode(v, Limits::CEILING).unwrap_or_default()
    }

    // OP-156 m.3 (f), L2-CLB-1
    #[test]
    fn only_a_body_matching_the_claim_value_is_kept() {
        let value = EqValue::Bytes(value_digest(10, 20).to_vec());
        assert_eq!(decode(Some(&value), &bytes(&body(10, 20))), Some((10, 20)));
        assert_eq!(decode(Some(&value), &bytes(&body(11, 20))), None);
        assert_eq!(decode(None, &bytes(&body(10, 20))), None);
        let backwards = EqValue::Bytes(value_digest(20, 10).to_vec());
        assert_eq!(decode(Some(&backwards), &bytes(&body(20, 10))), None);
        let extra = Value::Map(vec![
            (Value::text("checked_at"), Value::Unsigned(20)),
            (Value::text("last_change_at"), Value::Unsigned(10)),
            (Value::text("line"), Value::Unsigned(1)),
        ]);
        assert_eq!(decode(Some(&value), &bytes(&extra)), None);
    }
}
