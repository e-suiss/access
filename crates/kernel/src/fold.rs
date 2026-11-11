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

/// Whether `key` is a `claim`, `member` or `successor` key, the kinds a `claim` record writes
/// (L2-REC-2).
fn is_claim_key(key: &[u8]) -> bool {
    matches!(
        suiss_crypto::dcbor::decode(key, suiss_crypto::dcbor::Limits::CEILING),
        Ok(Value::Array(k)) if matches!(k.first(), Some(Value::Text(t)) if t == "claim" || t == "member" || t == "successor")
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

/// The freshest checkpoint a declared witness co-signed, as its ingested `checkpoint` Claim
/// says (SEC22, §13.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WitnessHead {
    /// Tree size.
    pub size: u64,
    /// Root hash.
    pub root: [u8; 32],
    /// Trusted time of the Claim, Unix ms.
    pub at: u64,
}

impl WitnessHead {
    /// A head of `size` and `root` claimed at `at`.
    #[must_use]
    pub const fn new(size: u64, root: [u8; 32], at: u64) -> Self {
        Self { size, root, at }
    }
}

/// How old a witness's checkpoint Claim may be for the rollback guard (SEC22, PD): 1 hour.
pub const WITNESS_FRESHNESS_MS: u64 = 3_600_000;

/// What the rollback guard asks of a recovery that cites checkpoint `N` (SEC22, §13.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Guard {
    /// Arm (i): the replica reproduces the witnesses' highest checkpoint and `N` is it.
    Pass,
    /// Arm (ii): no replica, or one behind the witnesses, or a witness without a fresh Claim.
    /// The meta-anchor root's general threshold is required and `(from, until]` is the declared
    /// lost suffix.
    Lossy {
        /// `N`.
        from: u64,
        /// The highest witnessed size.
        until: u64,
    },
}

/// Why the rollback guard refuses a recovery (SEC21, SEC22).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GuardError {
    /// `N` is below `R*`, the highest witnessed checkpoint the replica reproduces.
    #[error("rollback-guard")]
    Rollback,
    /// `N` is above every witnessed checkpoint, or its root is not the one a witness co-signed at
    /// that size.
    #[error("rollback-guard-unwitnessed")]
    Unwitnessed,
    /// Two witnesses co-signed different roots at one size and the recovery does not declare the
    /// fork, or declares one the Claims do not show.
    #[error("rollback-guard-fork")]
    Fork,
}

/// The rollback guard (SEC21, SEC22, §13.6): `heads` holds one entry per declared witness,
/// `None` where no Claim was ingested; `replica` is `R*`, the highest witnessed size the
/// provider-external replica reproduces, `None` without a reachable replica; `cited` is `N` with
/// its root; `fork` says the recovery declares a fork. Only Claims at most
/// [`WITNESS_FRESHNESS_MS`] old count. With a fork, `N` lies on the branch the replica
/// reproduces (at most `R*`), or without a replica below the first forked size.
///
/// # Errors
/// [`GuardError`].
pub fn rollback_guard(
    heads: &[Option<WitnessHead>],
    replica: Option<u64>,
    cited: (u64, [u8; 32]),
    fork: bool,
    now: u64,
) -> Result<Guard, GuardError> {
    let fresh: Vec<WitnessHead> = heads
        .iter()
        .flatten()
        .filter(|h| h.at <= now && now.saturating_sub(h.at) <= WITNESS_FRESHNESS_MS)
        .copied()
        .collect();
    let all_fresh = !heads.is_empty() && fresh.len() == heads.len();
    let mut roots: BTreeMap<u64, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for h in &fresh {
        roots.entry(h.size).or_default().insert(h.root);
    }
    let forked = roots.values().any(|r| r.len() > 1);
    if forked != fork {
        return Err(GuardError::Fork);
    }
    let (n, root) = cited;
    let highest = fresh
        .iter()
        .map(|h| h.size)
        .max()
        .ok_or(GuardError::Unwitnessed)?;
    if n > highest || roots.get(&n).is_some_and(|r| !r.contains(&root)) {
        return Err(GuardError::Unwitnessed);
    }
    if let Some(r) = replica
        && n < r
    {
        return Err(GuardError::Rollback);
    }
    let fork_at = roots
        .iter()
        .find_map(|(size, r)| (r.len() > 1).then_some(*size));
    let on_branch = match (fork_at, replica) {
        (None, _) => true,
        (Some(_), Some(r)) => n <= r,
        (Some(at), None) => n < at,
    };
    if !on_branch {
        return Err(GuardError::Fork);
    }
    match replica {
        Some(r) if all_fresh && !forked && r == highest && n == r => Ok(Guard::Pass),
        _ => Ok(Guard::Lossy {
            from: n,
            until: highest,
        }),
    }
}

/// Whether an Actor Intent Statement issued at `iat` is closed by a forced recovery at
/// `recovered_at`: issued before it and with a nonce the continuing lineage, archive included,
/// does not hold (`nonce_known`). A re-commit of a nonce the lineage holds returns its decision
/// and is never closed (TI-RT3, U28, SEC22 R1 (c), §9.6 `nonce-closed/pre-recovery`).
#[must_use]
pub const fn pre_recovery(iat: u64, recovered_at: u64, nonce_known: bool) -> bool {
    iat < recovered_at && !nonce_known
}

#[cfg(test)]
mod tests;
