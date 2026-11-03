//! PostgreSQL adapter of [`CourierStore`]: the outbox and cursor as `access_outbox_reader`
//! (OP-131 m.3), subject keys and undeliverable records as `access_app` under the realm's
//! scope (OP-12).

use access_store::Pool;
use access_store::identity::{self, Cursor, OutboxEvent, RealmId, TenantId, TenantTx};
use access_store::relay::Undelivered;

use crate::notify::NotifyError;
use crate::notify::courier::CONSUMER;
use crate::notify::ports::{CourierStore, SubjectKey};

/// The courier's two pools.
pub struct PgCourierStore {
    /// Logged in as a member of `access_outbox_reader`.
    pub reader: Pool,
    /// Logged in as a member of `access_app`.
    pub app: Pool,
}

impl CourierStore for PgCourierStore {
    async fn cursor(&self) -> Result<Cursor, NotifyError> {
        Ok(identity::cursor(&self.reader, CONSUMER).await?)
    }

    async fn poll(&self, after: Cursor, limit: u32) -> Result<Vec<OutboxEvent>, NotifyError> {
        Ok(identity::poll(&self.reader, after, limit).await?)
    }

    async fn ack(&self, at: Cursor) -> Result<(), NotifyError> {
        Ok(identity::ack(&self.reader, CONSUMER, at).await?)
    }

    async fn subject_key(
        &self,
        tenant: TenantId,
        realm: RealmId,
        subject: [u8; 16],
    ) -> Result<SubjectKey, NotifyError> {
        let mut tx = TenantTx::begin(&self.app, tenant, realm).await?;
        let row = tx.subject(subject, false).await?;
        tx.commit().await?;
        Ok(match row {
            None => SubjectKey::Missing,
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
        tx.commit().await?;
        Ok(())
    }
}
