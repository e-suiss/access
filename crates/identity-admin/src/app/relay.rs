//! `idp.relay.resend` and the undelivered Relay messages (OP-156 m.3 (c), Ek B 5401): an
//! administrator resends a message the courier gave up on. The resend is a new outbox row under
//! a new `CloudEvents` id citing the original; the original and its record stay (OP-73).

use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::{Actor, Realm};
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::resend::{ResendError, resend as queue_again};
use access_store::identity::TenantTx;
use serde_json::{Value, json};
use suiss_crypto::envelope::Kek;

use crate::AdminError;
use crate::domain::Invalid;

/// An event id as the courier writes it: a lower-case hyphenated UUID.
///
/// # Errors
/// [`Invalid::NoRelayMessage`] for anything else.
pub fn event_id(text: &str) -> Result<[u8; 16], Invalid> {
    let b = text.as_bytes();
    let shape = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        });
    if !shape {
        return Err(Invalid::NoRelayMessage);
    }
    let hex: Vec<u8> = b.iter().copied().filter(|c| *c != b'-').collect();
    let mut out = [0_u8; 16];
    for (o, pair) in out.iter_mut().zip(hex.as_chunks::<2>().0) {
        let pair = core::str::from_utf8(pair).map_err(|_| Invalid::NoRelayMessage)?;
        *o = u8::from_str_radix(pair, 16).map_err(|_| Invalid::NoRelayMessage)?;
    }
    Ok(out)
}

/// Refuses before the Exercise what cannot be resent: no such message, or shredded content.
///
/// # Errors
/// [`Invalid::NoRelayMessage`], [`Invalid::RelayShredded`]; [`AdminError`] when storage fails.
pub async fn check(t: &mut TenantTx, original: [u8; 16]) -> Result<(), AdminError> {
    match t.relay_recorded(original).await? {
        None => Err(Invalid::NoRelayMessage.into()),
        Some(r) if r.reason == "shredded" || r.payload.is_none() => {
            Err(Invalid::RelayShredded.into())
        }
        Some(_) => Ok(()),
    }
}

/// Queues the message again in the Exercise's transaction.
///
/// # Errors
/// [`Invalid::NoRelayMessage`], [`Invalid::RelayShredded`], [`Invalid::RelayExpired`];
/// [`AdminError::Unavailable`] when the seam fails.
pub async fn resend(
    t: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    original: [u8; 16],
    who: &Actor<'_>,
) -> Result<[u8; 16], AdminError> {
    let realm = Realm {
        tenant: t.tenant(),
        realm: t.realm().ok_or(AdminError::NoRealm)?,
        kek,
        ids,
    };
    match queue_again(
        t,
        &realm,
        &SystemEntropy,
        &SystemClock,
        EventId(original),
        who,
    )
    .await
    {
        Ok(id) => Ok(id.0),
        Err(ResendError::NotFound) => Err(Invalid::NoRelayMessage.into()),
        Err(ResendError::Shredded) => Err(Invalid::RelayShredded.into()),
        Err(ResendError::Expired) => Err(Invalid::RelayExpired.into()),
        Err(ResendError::Notify(_)) => Err(AdminError::Unavailable(String::from("relay"))),
    }
}

/// The realm's undelivered messages, oldest first, without their content: id, kind, reason,
/// Relay's status and the ids of their resends.
///
/// # Errors
/// [`AdminError`] when storage fails.
pub async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
    limit: u32,
) -> Result<Vec<(Value, u64)>, AdminError> {
    let mut out = Vec::new();
    for r in t.list_relay_undelivered(limit).await? {
        let id = EventId(r.event_id).to_string();
        if key.is_some_and(|k| k != id) {
            continue;
        }
        let resends: Vec<String> = t
            .relay_resends_of(r.event_id)
            .await?
            .into_iter()
            .map(|e| EventId(e).to_string())
            .collect();
        out.push((
            json!({
                "event_id": id,
                "kind": r.kind,
                "reason": r.reason,
                "relay_status": r.relay_status,
                "resends": resends,
            }),
            0,
        ));
    }
    Ok(out)
}
