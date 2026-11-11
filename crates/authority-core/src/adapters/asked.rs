//! What the Approval Surface shows of a waiting approval besides the render (§8.17.6.4,
//! OP-157 m.3 (l)): the requirement terms the `REQUIRE_ACTION` left unmet, and the contributions
//! recorded to the intent since then, read from the store without the leader.

use access_kernel::codec::Canonical;
use access_kernel::combinator::Unmet;
use access_kernel::combinator::codec::decision_from_value;
use access_kernel::digest::Digest;
use access_kernel::meta::{ContributionState, kind};
use access_kernel::record::{RecordEnvelope, RecordKind};
use access_store::Pool as PgPool;
use access_store::authority::{read_head, read_log, state_of};
use access_store::scope::DomainId;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;

/// Most records read after the decision for its contributions (PD); past it nothing is counted.
pub(super) const MAX_RECORDS: u64 = 1_024;

const PAGE: u64 = 128;

fn record(bytes: &[u8]) -> Result<RecordEnvelope, CoreError> {
    RecordEnvelope::from_bytes(bytes).map_err(|_| CoreError::Protocol("record"))
}

fn field<'a>(r: &'a RecordEnvelope, name: &str) -> Option<&'a Value> {
    r.fields.get(name).map(|f| &f.value)
}

/// The unmet terms of the decision recorded at `pos`; none for a record without them.
///
/// # Errors
/// [`CoreError`].
pub(super) async fn unmet(
    pool: &PgPool,
    scope: &DomainId,
    pos: u64,
) -> Result<Vec<Unmet>, CoreError> {
    let rows = read_log(pool, scope, pos, pos).await?;
    let Some(row) = rows.first() else {
        return Ok(Vec::new());
    };
    let r = record(&row.envelope)?;
    if r.header.kind != RecordKind::Decision {
        return Ok(Vec::new());
    }
    Ok(field(&r, "outcome")
        .and_then(|v| decision_from_value(v).ok())
        .map(|d| d.unmet)
        .unwrap_or_default())
}

fn contribution_keys(r: &RecordEnvelope, out: &mut Vec<Vec<u8>>) {
    let Some(Value::Array(effects)) = field(r, "effects") else {
        return;
    };
    for e in effects {
        let Value::Array(parts) = e else { continue };
        let Some(Value::Bytes(key)) = parts.first() else {
            continue;
        };
        if let Ok(Value::Array(items)) = dcbor::decode(key, Limits::CEILING)
            && matches!(items.first(), Some(Value::Text(k)) if k == kind::CONTRIBUTION)
        {
            out.push(key.clone());
        }
    }
}

/// The unconsumed contributions to `intent` recorded after `pos`, and whether every record up
/// to the head was read ([`MAX_RECORDS`] at most).
///
/// # Errors
/// [`CoreError`].
pub(super) async fn contributed(
    pool: &PgPool,
    scope: &DomainId,
    intent: &Digest,
    pos: u64,
) -> Result<(Vec<ContributionState>, bool), CoreError> {
    let head = read_head(pool, scope).await?.pos;
    let first = pos.saturating_add(1);
    let counted = head.saturating_sub(pos) <= MAX_RECORDS;
    let last = head.min(pos.saturating_add(MAX_RECORDS));
    let mut keys = Vec::new();
    let mut from = first;
    while from <= last {
        let to = from.saturating_add(PAGE).saturating_sub(1).min(last);
        for row in read_log(pool, scope, from, to).await? {
            let r = record(&row.envelope)?;
            if r.header.kind == RecordKind::Decision {
                contribution_keys(&r, &mut keys);
            }
        }
        from = to.saturating_add(1);
    }
    if keys.is_empty() {
        return Ok((Vec::new(), counted));
    }
    let mut out = Vec::new();
    for row in state_of(pool, scope, &keys).await? {
        let Some(state) = row
            .value
            .as_deref()
            .and_then(|v| dcbor::decode(v, Limits::CEILING).ok())
            .and_then(|v| ContributionState::from_value(&v).ok())
        else {
            continue;
        };
        if state.target == *intent && state.consumed.is_none() {
            out.push(state);
        }
    }
    out.sort_by_key(|c| c.since);
    Ok((out, counted))
}
