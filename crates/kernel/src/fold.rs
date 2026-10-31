//! State fold over the effects of decision records (L2-REC-2, L2-REC-3, TI-RT1): the only way
//! the authority state is built, from Genesis or incrementally commit by commit.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

use crate::record::{RecordEnvelope, RecordKind};

/// Longest state key in bytes (L2-REC-2).
pub const MAX_KEY: usize = 512;

/// A key's place in the state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its value; `None` once an effect removed it.
    pub value: Option<Value>,
    /// Position of the record that last changed it.
    pub version: u64,
}

/// The state: keys in bytewise order.
pub type State = BTreeMap<Vec<u8>, Entry>;

/// One effect: a key and its new value, `None` to remove it.
pub type Effect = (Vec<u8>, Option<Value>);

/// Why records cannot be folded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FoldError {
    /// Positions do not run 1, 2, 3, … in order.
    #[error("order")]
    Order,
    /// A record that is not a decision carries `effects`.
    #[error("effects-outside-decision")]
    OutsideDecision,
    /// A decision without a known `outcome`.
    #[error("outcome")]
    Outcome,
    /// A decision that is not `allow` carries `effects`.
    #[error("effects-without-allow")]
    WithoutAllow,
    /// An effect is not `[key]` or `[key, value]` with a key of 1 to [`MAX_KEY`] bytes, or the
    /// list is empty.
    #[error("effect")]
    Effect,
    /// A record names one key in two effects.
    #[error("duplicate-effect")]
    Duplicate,
    /// The record at position 0 is not a Genesis with `genesis-fields` (OP-141).
    #[error("genesis")]
    Genesis,
}

fn outcome(record: &RecordEnvelope) -> Result<&str, FoldError> {
    let Some(Value::Map(entries)) = record.fields.get("outcome").map(|f| &f.value) else {
        return Err(FoldError::Outcome);
    };
    let found = entries.iter().find_map(|(k, v)| match (k, v) {
        (Value::Text(k), Value::Text(v)) if k == "outcome" => Some(v.as_str()),
        _ => None,
    });
    match found {
        Some(o @ ("allow" | "deny" | "require_action")) => Ok(o),
        _ => Err(FoldError::Outcome),
    }
}

/// Whether a `claim` record admitted its Claim (L2-CLM-3).
fn admitted(record: &RecordEnvelope) -> bool {
    matches!(record.fields.get("disposition").map(|f| &f.value), Some(Value::Text(d)) if d == "admit")
}

/// Whether `key` is a `claim` key, the only kind a `claim` record writes (L2-REC-2).
fn is_claim_key(key: &[u8]) -> bool {
    matches!(
        suiss_crypto::dcbor::decode(key, suiss_crypto::dcbor::Limits::CEILING),
        Ok(Value::Array(k)) if matches!(k.first(), Some(Value::Text(t)) if t == "claim")
    )
}

/// The effects of one record, checked (L2-REC-2): `(key, None)` removes the key.
///
/// # Errors
/// [`FoldError`].
pub fn effects(record: &RecordEnvelope) -> Result<Vec<Effect>, FoldError> {
    let list = record.fields.get("effects").map(|f| &f.value);
    let claim = record.header.kind == RecordKind::Claim;
    if record.header.kind != RecordKind::Decision && !claim {
        return match list {
            Some(_) => Err(FoldError::OutsideDecision),
            None => Ok(Vec::new()),
        };
    }
    let allow = if claim {
        list.is_none() || admitted(record)
    } else {
        outcome(record)? == "allow"
    };
    let Some(list) = list else {
        return Ok(Vec::new());
    };
    if !allow {
        return Err(FoldError::WithoutAllow);
    }
    let Value::Array(items) = list else {
        return Err(FoldError::Effect);
    };
    if items.is_empty() {
        return Err(FoldError::Effect);
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (key, value) = match item {
            Value::Array(e) => match e.as_slice() {
                [Value::Bytes(k)] => (k, None),
                [Value::Bytes(k), v] => (k, Some(v.clone())),
                _ => return Err(FoldError::Effect),
            },
            _ => return Err(FoldError::Effect),
        };
        if key.is_empty() || key.len() > MAX_KEY {
            return Err(FoldError::Effect);
        }
        if claim && !is_claim_key(key) {
            return Err(FoldError::OutsideDecision);
        }
        if !seen.insert(key.as_slice()) {
            return Err(FoldError::Duplicate);
        }
        out.push((key.clone(), value));
    }
    Ok(out)
}

/// Applies one record's effects to `state` (L2-REC-3).
///
/// # Errors
/// [`FoldError`]; `state` is unchanged on error.
pub fn apply(state: &mut State, record: &RecordEnvelope) -> Result<(), FoldError> {
    let version = record.header.pos;
    for (key, value) in effects(record)? {
        state.insert(key, Entry { value, version });
    }
    Ok(())
}

/// The state Genesis creates, at version 0 (C4, OP-141 m.6).
///
/// # Errors
/// [`FoldError::Genesis`].
pub fn genesis(record: &RecordEnvelope) -> Result<State, FoldError> {
    if record.header.kind != RecordKind::Genesis || record.header.pos != 0 {
        return Err(FoldError::Genesis);
    }
    let domain = record.domain().map_err(|_| FoldError::Genesis)?;
    let fields = record
        .fields
        .iter()
        .map(|(k, f)| (k.clone(), f.value.clone()))
        .collect();
    let effects = crate::meta::genesis_effects(&domain, &fields).map_err(|_| FoldError::Genesis)?;
    Ok(effects
        .into_iter()
        .filter_map(|(k, v)| {
            v.map(|v| {
                (
                    k,
                    Entry {
                        value: Some(v),
                        version: 0,
                    },
                )
            })
        })
        .collect())
}

/// The state after records `1..=n`, given in position order (L2-REC-3).
///
/// # Errors
/// [`FoldError`].
pub fn fold(records: &[RecordEnvelope]) -> Result<State, FoldError> {
    let mut state = State::new();
    let mut expected: u64 = 1;
    for record in records {
        if record.header.pos != expected {
            return Err(FoldError::Order);
        }
        apply(&mut state, record)?;
        expected = expected.checked_add(1).ok_or(FoldError::Order)?;
    }
    Ok(state)
}

#[cfg(test)]
mod tests;
