//! The outbox [`Notifier`] (OP-10, OP-20, E42 m.1): seals the message under the subject's DEK, or
//! the DEK of an address challenge for an address with no account yet, and adds it to
//! `identity_outbox` in the caller's transaction.

use access_store::identity::TenantTx;
use suiss_crypto::envelope::Dek;

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
    entropy: &'a (dyn Entropy + Sync),
    clock: &'a (dyn Clock + Sync),
}

impl<'a> OutboxNotifier<'a> {
    /// A notifier for `realm`.
    #[must_use]
    pub const fn new(
        realm: &'a Realm<'a>,
        entropy: &'a (dyn Entropy + Sync),
        clock: &'a (dyn Clock + Sync),
    ) -> Self {
        Self {
            realm,
            entropy,
            clock,
        }
    }
}

/// The DEK a message to `subject` is sealed under: the subject's, or that of the address
/// challenge of an address with no account yet (OP-153 m.3 (g)).
///
/// # Errors
/// [`NotifyError::NoSubject`] when neither exists or the key was shredded; [`NotifyError`].
pub(crate) async fn recipient_key(
    realm: &Realm<'_>,
    tx: &mut TenantTx,
    subject: [u8; 16],
) -> Result<Dek, NotifyError> {
    if let Some(row) = tx.subject(subject, false).await? {
        return subject_key(realm, &row).map_err(|_| NotifyError::NoSubject);
    }
    // OP-153 m.3 (g)
    let key = tx
        .challenge_key(subject)
        .await?
        .ok_or(NotifyError::NoSubject)?;
    let wrapped = key.wrapped_dek.ok_or(NotifyError::NoSubject)?;
    if key.kek_id != realm.kek.id() {
        return Err(NotifyError::NoSubject);
    }
    realm.kek.unwrap(&wrapped).map_err(|_| NotifyError::Seal)
}

impl Notifier for OutboxNotifier<'_> {
    async fn notify(&self, tx: &mut TenantTx, message: &Message) -> Result<EventId, NotifyError> {
        message.validate()?;
        if tx.tenant() != self.realm.tenant || tx.realm() != Some(self.realm.realm) {
            return Err(NotifyError::NoSubject);
        }
        let dek = recipient_key(self.realm, tx, message.subject).await?;
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
