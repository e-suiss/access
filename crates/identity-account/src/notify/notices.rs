//! Security-relevant authority events go to the person at once (OP-156 m.3 (c), Ek B 5294,
//! §8.6): a `SecurityAuthorityNotice` through Relay, on by default and closed only by
//! `idp.realm.security_notices_close`. The notice is information: it carries no "action
//! required" label, only "If you didn't expect this: Review", and authority never waits on its
//! delivery (INV-24). Instance termination is the event the authority plane derives today; a
//! new sub-delegation and a new domain's acceptance come with their event kinds.

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_internal_api::events::{Detail, Event, Kind};
use access_store::identity::TenantTx;

use crate::app::Realm;
use crate::app::vault::reveal_with_kek;
use crate::notify::NotifyError;
use crate::notify::envelope::EventId;
use crate::notify::message::{Address, Body, Message, SecurityEvent};
use crate::notify::notifier::OutboxNotifier;
use crate::notify::ports::Notifier as _;
use crate::ports::{Clock, Entropy};
use suiss_crypto::envelope::Kek;

/// The account page a notice's Review link opens, under the realm issuer.
pub const REVIEW_PATH: &str = "/account/security";

/// The security event an authority event is, and the Party it concerns; `None` for events that
/// are not security notices.
#[must_use]
pub fn security_event(e: &Event) -> Option<(SecurityEvent, [u8; 16])> {
    match (e.kind, &e.detail) {
        (Kind::InstanceTerminated, Detail::Instance { party }) => {
            Some((SecurityEvent::InstanceEnded, party.0))
        }
        _ => None,
    }
}

/// The notice body: the Review link under `issuer`, and no Revoke link once nothing is left to
/// revoke.
#[must_use]
pub fn notice_body(event: SecurityEvent, name: &str, issuer: &str, at_ms: u64) -> Body {
    let review = format!("{}{REVIEW_PATH}", issuer.trim_end_matches('/'));
    Body::SecurityAuthorityNotice {
        event,
        name: name.chars().take(200).collect(),
        review_link: Secret::new(review),
        revoke_link: None,
        at_ms,
    }
}

/// Queues the notice of `event` to `subject` in `tx`, at the subject's registered contact
/// address; `None` when it has none.
///
/// # Errors
/// [`NotifyError`]; the caller rolls back and the event is read again.
#[expect(
    clippy::too_many_arguments,
    reason = "the realm, the ports and the event, each needed once"
)]
pub async fn queue(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    entropy: &(dyn Entropy + Sync),
    clock: &(dyn Clock + Sync),
    subject: [u8; 16],
    event: SecurityEvent,
    (name, issuer): (&str, &str),
    at_ms: u64,
) -> Result<Option<EventId>, NotifyError> {
    let realm = Realm {
        tenant: tx.tenant(),
        realm: tx.realm().ok_or(NotifyError::NoSubject)?,
        kek,
        ids,
    };
    let Some((kind, stored)) = tx.contact(subject).await? else {
        return Ok(None);
    };
    let Some(value) = reveal_with_kek(tx, kek, subject, &stored)
        .await
        .map_err(|_| NotifyError::KeyUnavailable)?
    else {
        return Ok(None);
    };
    let to = if kind == "phone" {
        Address::Phone(value)
    } else {
        Address::Email(value)
    };
    let valid_since_ms = if matches!(to, Address::Email(_)) {
        Some(
            tx.mailbox_since(subject)
                .await?
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(1)
                .max(1),
        )
    } else {
        None
    };
    let message = Message {
        subject,
        to,
        locale: None,
        valid_since_ms,
        body: notice_body(event, name, issuer, at_ms),
    };
    let id = OutboxNotifier::new(&realm, entropy, clock)
        .notify(tx, &message)
        .await?;
    Ok(Some(id))
}
