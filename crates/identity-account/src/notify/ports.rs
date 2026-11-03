//! What the Relay seam needs from the outside world (OP-63).

use std::future::Future;

use access_store::identity::{Cursor, OutboxEvent, RealmId, TenantId, TenantTx};
use access_store::relay::Undelivered;
use suiss_crypto::envelope::Kek;

use crate::notify::NotifyError;
use crate::notify::delivery::{CloudEvent, SendFailure};
use crate::notify::envelope::EventId;
use crate::notify::message::Message;

/// Queues a message to a person inside the caller's transaction (E42 m.1, OP-10): it reaches
/// Relay only if the transaction commits, and a rollback leaves nothing.
pub trait Notifier {
    /// Enqueues `message`; returns its `CloudEvents` id.
    ///
    /// # Errors
    /// [`NotifyError`]; the caller rolls its transaction back.
    fn notify(
        &self,
        tx: &mut TenantTx,
        message: &Message,
    ) -> impl Future<Output = Result<EventId, NotifyError>> + Send;
}

/// Relay's event intake (E42, OP-146 m.4 (b)).
pub trait RelayPort: Send + Sync {
    /// Posts one event; Relay deduplicates by its id.
    fn send(&self, event: &CloudEvent) -> impl Future<Output = Result<(), SendFailure>> + Send;
}

/// The realm KEKs the courier unwraps subject DEKs with (OP-42, OP-135).
pub trait RealmKeys: Send + Sync {
    /// The realm's KEK with id `kek_id`, when this process holds it.
    fn kek(
        &self,
        tenant: TenantId,
        realm: RealmId,
        kek_id: &str,
    ) -> Option<&(dyn Kek + Send + Sync)>;
}

/// A subject's wrapped DEK as the courier finds it.
pub enum SubjectKey {
    /// No such subject in the realm.
    Missing,
    /// Shredded (OP-73).
    Shredded,
    /// Wrapped by the realm KEK `kek_id`.
    Wrapped {
        /// KEK id.
        kek_id: String,
        /// Wrapped DEK.
        wrapped: Vec<u8>,
    },
}

/// The courier's storage: the outbox and its cursor as `access_outbox_reader` (OP-131), and
/// realm-scoped reads and records as `access_app`.
pub trait CourierStore: Send + Sync {
    /// The courier's cursor.
    fn cursor(&self) -> impl Future<Output = Result<Cursor, NotifyError>> + Send;
    /// Outbox events after `after`, in `(xid, id)` order.
    fn poll(
        &self,
        after: Cursor,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<OutboxEvent>, NotifyError>> + Send;
    /// Moves the cursor forward to `at`.
    fn ack(&self, at: Cursor) -> impl Future<Output = Result<(), NotifyError>> + Send;
    /// The subject's wrapped DEK.
    fn subject_key(
        &self,
        tenant: TenantId,
        realm: RealmId,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<SubjectKey, NotifyError>> + Send;
    /// Records an undeliverable message once.
    fn undelivered(
        &self,
        tenant: TenantId,
        realm: RealmId,
        record: &Undelivered<'_>,
    ) -> impl Future<Output = Result<(), NotifyError>> + Send;
}
