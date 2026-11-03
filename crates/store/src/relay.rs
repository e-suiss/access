//! Relay messages the courier passed without delivering (E42 m.5, OP-131, OP-146 m.4 (b)).
//! The outbox row itself stays; this records why, so nothing is lost (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{Cursor, TenantTx};

/// One undeliverable message.
pub struct Undelivered<'a> {
    /// The `CloudEvents` id, the Relay idempotency key.
    pub event_id: [u8; 16],
    /// Where it sits in the outbox.
    pub at: Cursor,
    /// Outbox kind.
    pub kind: &'a str,
    /// `malformed`, `no_subject`, `shredded`, `expired` or `rejected`.
    pub reason: &'a str,
    /// Relay's HTTP status, for `rejected`.
    pub relay_status: Option<u16>,
}

/// A recorded undeliverable message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndeliveredRow {
    /// The `CloudEvents` id.
    pub event_id: [u8; 16],
    /// Outbox kind.
    pub kind: String,
    /// Reason code.
    pub reason: String,
    /// Relay's HTTP status.
    pub relay_status: Option<u16>,
}

impl TenantTx {
    /// Records `u` once; a second record of the same event is a no-op (redelivery).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn relay_undelivered(&mut self, u: &Undelivered<'_>) -> Result<(), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let xid = i64::try_from(u.at.xid).map_err(|_| StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.relay_undelivered
                (tenant_id, realm_id, event_id, outbox_xid, outbox_id, kind, reason, relay_status)
             VALUES ($1, $2, $3, $4::bigint::text::xid8, $5, $6, $7, $8)
             ON CONFLICT (tenant_id, realm_id, event_id) DO NOTHING",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(u.event_id),
            xid,
            u.at.id,
            u.kind,
            u.reason,
            u.relay_status.map(i32::from),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The realm's undeliverable messages, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn list_relay_undelivered(
        &mut self,
        limit: u32,
    ) -> Result<Vec<UndeliveredRow>, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let rows = sqlx::query!(
            "SELECT event_id, kind, reason, relay_status FROM access.relay_undelivered
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY outbox_xid, outbox_id LIMIT $3",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(UndeliveredRow {
                    event_id: r.event_id.into_bytes(),
                    kind: r.kind,
                    reason: r.reason,
                    relay_status: r
                        .relay_status
                        .map(u16::try_from)
                        .transpose()
                        .map_err(|_| StoreError::Corrupt)?,
                })
            })
            .collect()
    }

    /// Shreds a `purging` subject's DEK (OP-73, OP-145 m.3); for the courier tests only, the
    /// purge job owns the real path.
    ///
    /// # Errors
    /// [`StoreError`].
    #[cfg(feature = "testing")]
    pub async fn shred_subject_for_test(&mut self, subject: [u8; 16]) -> Result<bool, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let n = sqlx::query!(
            "UPDATE access.identity_subjects SET wrapped_dek = NULL, shredded_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                AND status = 'purging' AND shredded_at IS NULL",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(subject),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
