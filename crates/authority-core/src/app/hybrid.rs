//! A signed receipt or PAP as the decision point keeps and sends it (CR-42 m.4, OP-159 m.15
//! (b)): one `COSE_Sign1` with its key excerpt, or, under a hybrid domain, the carrier
//! `[classic, pq]` with the pair of excerpts `[classic, pq]` in the excerpt slot. On the wire
//! the pair is split into `excerpt` and `pq_excerpt`.

use suiss_crypto::dcbor::{self, Limits, Value};

/// The kept excerpt slot of a hybrid artefact: `[classic, pq]`.
///
/// # Errors
/// The pair cannot be encoded.
pub fn pair(classic: &[u8], pq: &[u8]) -> Result<Vec<u8>, dcbor::EncodeError> {
    dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(classic.to_vec()),
            Value::Bytes(pq.to_vec()),
        ]),
        Limits::CEILING,
    )
}

/// The classical excerpt and, for a hybrid artefact, the ML-DSA one, from a kept excerpt slot.
/// A tagged `COSE_Sign1` is a lone excerpt; anything else that is not the pair is returned
/// whole, and the verifier refuses it.
#[must_use]
pub fn split(kept: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    if kept.first() != Some(&0xd2)
        && let Ok(Value::Array(items)) = dcbor::decode(kept, Limits::CEILING)
        && let [Value::Bytes(classic), Value::Bytes(pq)] = items.as_slice()
    {
        return (classic.clone(), Some(pq.clone()));
    }
    (kept.to_vec(), None)
}
