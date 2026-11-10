//! Sending an undeliverable Relay message again (OP-156 m.3 (c), Ek B 5401): the message the
//! courier passed is opened under the subject's key and sealed again as a new outbox row under a
//! new `CloudEvents` id, so Relay does not take it for a duplicate. The original row and its
//! undeliverable record stay (OP-73); `relay_resends` links the two and names who asked, and the
//! identity audit log records `relay.resent`. A message whose subject was shredded cannot be
//! read and is not resent; neither is a code or link that has expired.

use access_store::audit::AuditEvent;
use access_store::identity::TenantTx;
use access_store::relay::Resend;

use crate::app::{Actor, Realm};
use crate::notify::NotifyError;
use crate::notify::envelope::{EventId, Header, parse, seal};
use crate::notify::message::KIND_PREFIX;
use crate::notify::notifier::recipient_key;
use crate::ports::{Clock, Entropy};

/// The identity audit event of a resend.
pub const AUDIT_EVENT: &str = "relay.resent";

/// Why a message was not resent.
#[derive(Debug, thiserror::Error)]
pub enum ResendError {
    /// No undeliverable message with that id in the realm.
    #[error("no such undeliverable message")]
    NotFound,
    /// The subject's key was shredded; the content is gone (OP-73).
    #[error("content shredded")]
    Shredded,
    /// The code or link it carries has expired; a new one must be asked for.
    #[error("message expired")]
    Expired,
    /// The seam failed.
    #[error(transparent)]
    Notify(#[from] NotifyError),
}

impl From<access_store::StoreError> for ResendError {
    fn from(e: access_store::StoreError) -> Self {
        Self::Notify(NotifyError::Store(e))
    }
}

/// Queues the undeliverable message `original` again in `tx`; returns the new message's id.
/// The caller commits `tx` with the admin Exercise that asked for it.
///
/// # Errors
/// [`ResendError`]; the caller rolls `tx` back.
pub async fn resend(
    tx: &mut TenantTx,
    realm: &Realm<'_>,
    entropy: &(dyn Entropy + Sync),
    clock: &(dyn Clock + Sync),
    original: EventId,
    who: &Actor<'_>,
) -> Result<EventId, ResendError> {
    if tx.tenant() != realm.tenant || tx.realm() != Some(realm.realm) {
        return Err(ResendError::NotFound);
    }
    let recorded = tx
        .relay_recorded(original.0)
        .await?
        .ok_or(ResendError::NotFound)?;
    if recorded.reason == "shredded" {
        return Err(ResendError::Shredded);
    }
    if !recorded.kind.starts_with(KIND_PREFIX) {
        return Err(ResendError::NotFound);
    }
    let payload = recorded.payload.ok_or(ResendError::NotFound)?;
    let env = parse(&payload).map_err(|_| ResendError::NotFound)?;
    let dek = match recipient_key(realm, tx, env.header.subject).await {
        Ok(d) => d,
        Err(NotifyError::NoSubject) => return Err(ResendError::Shredded),
        Err(e) => return Err(e.into()),
    };
    let message = env
        .open(&recorded.kind, &dek)
        .map_err(|_| ResendError::NotFound)?;
    let now = clock.now_ms();
    if message.body.expires_at_ms().is_some_and(|e| now >= e) {
        return Err(ResendError::Expired);
    }
    let event = EventId::from_random(entropy.salt().map_err(|_| NotifyError::Random)?);
    let header = Header {
        event,
        occurred_ms: now,
        ..env.header
    };
    let sealed = seal(&header, &dek, &message).map_err(|_| NotifyError::Seal)?;
    tx.outbox(&recorded.kind, &sealed).await?;
    tx.relay_resend(&Resend {
        event_id: event.0,
        original_event_id: original.0,
        actor: who.actor,
        correlation: who.correlation,
    })
    .await?;
    let target = original.to_string();
    tx.audit(&AuditEvent {
        event_type: AUDIT_EVENT,
        actor: who.actor,
        target: &target,
        correlation: who.correlation,
    })
    .await?;
    Ok(event)
}
