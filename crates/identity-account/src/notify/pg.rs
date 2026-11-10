//! PostgreSQL adapter of [`CourierStore`]: the outbox and cursor as `access_outbox_reader`
//! (OP-131 m.3), subject keys and undeliverable records as `access_app` under the realm's
//! scope (OP-12).

use std::time::Duration;

use access_store::audit::AuditEvent;
use access_store::identity::{self, Cursor, OutboxEvent, RealmId, TenantId, TenantTx};
use access_store::relay::{self, CourierLease, Undelivered};
use access_store::{Pool, StoreError};

/// The identity audit event of a message the courier passed without delivering.
pub const AUDIT_EVENT: &str = "relay.undelivered";

use crate::notify::NotifyError;
use crate::notify::courier::CONSUMER;
use crate::notify::envelope::EventId;
use crate::notify::message::KIND_PREFIX;
use crate::notify::ports::{CourierStore, SubjectKey};

/// The courier's two pools.
pub struct PgCourierStore {
    /// Logged in as a member of `access_outbox_reader`.
    pub reader: Pool,
    /// Logged in as a member of `access_app`.
    pub app: Pool,
}

impl CourierStore for PgCourierStore {
    async fn lease(
        &self,
        holder: &str,
        ttl: Duration,
    ) -> Result<Option<CourierLease>, NotifyError> {
        Ok(relay::acquire_courier_lease(&self.reader, CONSUMER, holder, ttl).await?)
    }

    async fn release(&self, lease: &CourierLease) -> Result<(), NotifyError> {
        Ok(relay::release_courier_lease(&self.reader, lease).await?)
    }

    async fn cursor(&self) -> Result<Cursor, NotifyError> {
        Ok(identity::cursor(&self.reader, CONSUMER).await?)
    }

    async fn lag_ms(&self) -> Result<Option<u64>, NotifyError> {
        let at = identity::cursor(&self.reader, CONSUMER).await?;
        Ok(relay::oldest_pending_ms(&self.reader, at, KIND_PREFIX).await?)
    }

    async fn poll(&self, after: Cursor, limit: u32) -> Result<Vec<OutboxEvent>, NotifyError> {
        Ok(identity::poll(&self.reader, after, limit).await?)
    }

    async fn ack(&self, lease: &CourierLease, at: Cursor) -> Result<(), NotifyError> {
        match relay::ack_fenced(&self.reader, lease, at).await {
            Err(StoreError::LeaseLost) => Err(NotifyError::LeaseLost),
            r => Ok(r?),
        }
    }

    async fn subject_key(
        &self,
        tenant: TenantId,
        realm: RealmId,
        subject: [u8; 16],
    ) -> Result<SubjectKey, NotifyError> {
        let mut tx = TenantTx::begin(&self.app, tenant, realm).await?;
        let row = tx.subject(subject, false).await?;
        // OP-153 m.3 (g)
        let challenge = if row.is_none() {
            tx.challenge_key(subject).await?
        } else {
            None
        };
        tx.commit().await?;
        Ok(match row {
            None => match challenge {
                None => SubjectKey::Missing,
                Some(c) => match c.wrapped_dek {
                    None => SubjectKey::Shredded,
                    Some(wrapped) => SubjectKey::Wrapped {
                        kek_id: c.kek_id,
                        wrapped,
                    },
                },
            },
            Some(r) => match r.wrapped_dek {
                None => SubjectKey::Shredded,
                Some(wrapped) => SubjectKey::Wrapped {
                    kek_id: r.kek_id,
                    wrapped,
                },
            },
        })
    }

    async fn undelivered(
        &self,
        tenant: TenantId,
        realm: RealmId,
        record: &Undelivered<'_>,
    ) -> Result<(), NotifyError> {
        let mut tx = TenantTx::begin(&self.app, tenant, realm).await?;
        tx.relay_undelivered(record).await?;
        // OP-156 m.3 (c), OP-41
        let target = EventId(record.event_id).to_string();
        tx.audit(&AuditEvent {
            event_type: AUDIT_EVENT,
            actor: CONSUMER,
            target: &target,
            correlation: &target,
        })
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
