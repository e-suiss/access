//! The outbox [`Notifier`] (OP-10, OP-20, E42 m.1): seals the message under the subject's DEK
//! and adds it to `identity_outbox` in the caller's transaction.

use access_store::identity::TenantTx;

use crate::app::Realm;
use crate::app::sealing::subject_key;
use crate::notify::NotifyError;
use crate::notify::envelope::{EventId, Header, seal};
use crate::notify::message::Message;
use crate::notify::ports::Notifier;
use crate::ports::{Clock, Entropy};

/// The production [`Notifier`] for one realm.
pub struct OutboxNotifier<'a> {
    realm: &'a Realm<'a>,
    entropy: &'a dyn Entropy,
    clock: &'a dyn Clock,
}

impl<'a> OutboxNotifier<'a> {
    /// A notifier for `realm`.
    #[must_use]
    pub const fn new(realm: &'a Realm<'a>, entropy: &'a dyn Entropy, clock: &'a dyn Clock) -> Self {
        Self {
            realm,
            entropy,
            clock,
        }
    }
}

impl Notifier for OutboxNotifier<'_> {
    async fn notify(&self, tx: &mut TenantTx, message: &Message) -> Result<EventId, NotifyError> {
        message.validate()?;
        if tx.tenant() != self.realm.tenant || tx.realm() != Some(self.realm.realm) {
            return Err(NotifyError::NoSubject);
        }
        let row = tx
            .subject(message.subject, false)
            .await?
            .ok_or(NotifyError::NoSubject)?;
        let dek = subject_key(self.realm, &row).map_err(|_| NotifyError::NoSubject)?;
        let event = EventId::from_random(self.entropy.salt().map_err(|_| NotifyError::Random)?);
        let header = Header {
            tenant: *self.realm.tenant.as_bytes(),
            realm: *self.realm.realm.as_bytes(),
            event,
            subject: message.subject,
            occurred_ms: self.clock.now_ms(),
        };
        let payload = seal(&header, &dek, message).map_err(|_| NotifyError::Seal)?;
        tx.outbox(message.body.kind(), &payload).await?;
        Ok(event)
    }
}
