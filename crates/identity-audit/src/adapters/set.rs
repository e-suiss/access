//! Security Event Token rendering of an audit record (RFC 8417, OP-41, CMP-27): the full
//! taxonomy event as one `events` member under the Access audit namespace, with the common `txn`
//! and the time of the event (`toe`). Signing is the issuing key's (`secevent+jwt`).

use serde_json::{Map, Value, json};
use suiss_crypto::signer::Signer;

use crate::domain::record::{AuditRecord, Scope, uuid_text};
use crate::domain::taxonomy::{TaxonomyError, entry};

/// The SET's JOSE `typ` (RFC 8417 §2.3).
pub const TYP: &str = "secevent+jwt";

/// Event type URI prefix of the audit stream; the event name follows.
pub const EVENT_PREFIX: &str = "urn:suiss:access:audit:";

const fn seconds(ms: u64) -> u64 {
    ms / 1000
}

/// The SET claims of `record` issued by `iss`.
///
/// # Errors
/// [`TaxonomyError::Unknown`] for an event outside the taxonomy; nothing is rendered.
pub fn claims(record: &AuditRecord, iss: &str) -> Result<Value, TaxonomyError> {
    let e = entry(&record.event)?;
    let mut body = Map::new();
    body.insert("actor".into(), record.actor.as_str().into());
    body.insert("target".into(), record.target.as_str().into());
    body.insert("outcome".into(), e.outcome.word().into());
    body.insert("occurred_at".into(), record.occurred_at_ms.into());
    body.insert("recorded_at".into(), record.recorded_at_ms.into());
    if let Some(c) = record.checkpoint_at_ms {
        body.insert("checkpoint_at".into(), c.into());
    }
    if let Some(t) = &record.tenant {
        body.insert("tenant".into(), uuid_text(t).into());
    }
    if record.scope != Scope::None {
        body.insert("scope".into(), record.scope.text().into());
    }
    if let Some(r) = &record.reason {
        body.insert("reason".into(), r.as_str().into());
    }
    if let Some(c) = e.caep() {
        body.insert("caep".into(), c.into());
    }
    let mut events = Map::new();
    events.insert(
        format!("{EVENT_PREFIX}{}", record.event),
        Value::Object(body),
    );
    Ok(json!({
        "iss": iss,
        "jti": record.id,
        "iat": seconds(record.recorded_at_ms),
        "toe": seconds(record.occurred_at_ms),
        "txn": record.txn,
        "events": events,
    }))
}

/// Why a SET could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum SetError {
    /// The event is outside the taxonomy.
    #[error("taxonomy: {0}")]
    Taxonomy(#[from] TaxonomyError),
    /// The claims could not be signed.
    #[error("jose: {0}")]
    Jose(#[from] access_crypto::jose::JoseError),
    /// The claims could not be serialised.
    #[error("encode")]
    Encode,
}

/// The compact SET of `record`, signed by `signer` under key id `kid`.
///
/// # Errors
/// [`SetError`].
pub fn sign(
    record: &AuditRecord,
    iss: &str,
    signer: &dyn Signer,
    kid: &[u8; 32],
) -> Result<String, SetError> {
    let payload = serde_json::to_vec(&claims(record, iss)?).map_err(|_| SetError::Encode)?;
    Ok(access_crypto::jose::sign_compact(
        signer, kid, TYP, &payload,
    )?)
}
