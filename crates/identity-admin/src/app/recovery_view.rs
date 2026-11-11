//! The governing domain's recovery declaration and its handover and recovery history (§8.12,
//! §8.17.9.7, §13.6, OP-158 m.3 (m)): read from the authority state and outbox, never a
//! decision input.

use access_internal_api::events::{Detail, Event, Kind};
use access_kernel::codec::Canonical as _;
use access_kernel::recovery::{KeyHolding, RecoveryEntry, entry_key};
use access_store::Pool;
use access_store::scope::DomainId;
use serde_json::{Value, json};
use suiss_crypto::dcbor::{self, Limits};

use crate::AdminError;
use crate::app::rest::rfc3339;

/// Most handover and recovery events the history reads (PD).
const MAX_EVENTS: u32 = 1_000;

/// Why a domain without an entry cannot be recovered.
pub const NO_ENTRY: &str = "no-recovery-entry";

/// The recovery view of `domain`.
///
/// # Errors
/// [`AdminError`] when the store cannot be read.
pub async fn view(app: &Pool, domain: &DomainId) -> Result<Value, AdminError> {
    let entry = access_store::authority::state_of(app, domain, &[entry_key()])
        .await?
        .into_iter()
        .find_map(|r| r.value)
        .and_then(|v| dcbor::decode(&v, Limits::CEILING).ok())
        .and_then(|v| RecoveryEntry::from_value(&v).ok());
    let mut out = match &entry {
        Some(e) => json!({
            "recovery": "available",
            "recovery_threshold": { "k": e.threshold, "n": e.keys.len() },
            "held_on": match e.held_on {
                KeyHolding::Device => "device",
                KeyHolding::Offline => "offline",
            },
        }),
        None => json!({ "recovery": "not_available", "recovery_reason": NO_ENTRY }),
    };
    let mut history = Vec::new();
    for row in access_store::authority::read_outbox(app, domain, (0, 0), MAX_EVENTS).await? {
        let Ok(e) = Event::from_bytes(&row.event) else {
            continue;
        };
        let Detail::Domain { position } = e.detail else {
            continue;
        };
        match e.kind {
            Kind::DomainRecovered => {
                let kept = position.saturating_sub(1);
                let lost_after = access_store::authority::read_log(app, domain, kept, kept)
                    .await?
                    .first()
                    .map_or(e.at, |r| r.recorded_at);
                history.push(json!({
                    "kind": "recovered",
                    "position": position.to_string(),
                    "at": rfc3339(e.at),
                    "lost_after": rfc3339(lost_after),
                }));
            }
            Kind::DomainHandover => history.push(json!({
                "kind": "handover",
                "position": position.to_string(),
                "at": rfc3339(e.at),
            })),
            _ => {}
        }
    }
    if let Some(o) = out.as_object_mut() {
        o.insert(String::from("history"), Value::Array(history));
    }
    Ok(out)
}
