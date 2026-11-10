//! Relay messages the courier passed without delivering (E42 m.5, OP-131, OP-146 m.4 (b)).
//! The outbox row itself stays; this records why, so nothing is lost (OP-73). Also the single
//! courier lease of an outbox consumer and the cursor it fences, the courier's lag, and the
//! record of a resent message (OP-156 m.3 (c)).

use std::time::Duration;

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{Cursor, TenantTx};

/// A held courier lease: the holder and the epoch that fences its cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CourierLease {
    /// The consumer it is the lease of.
    pub consumer: String,
    /// Who holds it.
    pub holder: String,
    /// Grows on every change of holder.
    pub epoch: u64,
}

/// Takes or renews `consumer`'s lease for `holder` for `ttl`; `None` while another holder's
/// lease is live. The epoch stays on a renewal and grows on any other take.
///
/// # Errors
/// [`StoreError`].
pub async fn acquire_courier_lease(
    reader: &PgPool,
    consumer: &str,
    holder: &str,
    ttl: Duration,
) -> Result<Option<CourierLease>, StoreError> {
    let ms = i64::try_from(ttl.as_millis()).map_err(|_| StoreError::Range)?;
    let epoch = sqlx::query_scalar!(
        "INSERT INTO access_ops.courier_leases AS l (consumer, holder, epoch, expires_at)
         VALUES ($1, $2, 1, now() + $3::bigint * interval '1 millisecond')
         ON CONFLICT (consumer) DO UPDATE SET
           holder = EXCLUDED.holder,
           epoch = CASE WHEN l.holder = EXCLUDED.holder AND l.released_at IS NULL
                          AND l.expires_at > now() THEN l.epoch ELSE l.epoch + 1 END,
           acquired_at = CASE WHEN l.holder = EXCLUDED.holder AND l.released_at IS NULL
                          AND l.expires_at > now() THEN l.acquired_at ELSE now() END,
           expires_at = EXCLUDED.expires_at,
           released_at = NULL
         WHERE (l.holder = EXCLUDED.holder AND l.released_at IS NULL)
            OR l.expires_at <= now() OR l.released_at IS NOT NULL
         RETURNING l.epoch",
        consumer,
        holder,
        ms,
    )
    .fetch_optional(reader)
    .await?;
    epoch
        .map(|e| {
            Ok(CourierLease {
                consumer: consumer.to_owned(),
                holder: holder.to_owned(),
                epoch: u64::try_from(e).map_err(|_| StoreError::Corrupt)?,
            })
        })
        .transpose()
}

/// Gives a held lease up, so another node need not wait for it to expire.
///
/// # Errors
/// [`StoreError`].
pub async fn release_courier_lease(
    reader: &PgPool,
    lease: &CourierLease,
) -> Result<(), StoreError> {
    let epoch = i64::try_from(lease.epoch).map_err(|_| StoreError::Range)?;
    sqlx::query!(
        "UPDATE access_ops.courier_leases SET released_at = now()
          WHERE consumer = $1 AND holder = $2 AND epoch = $3 AND released_at IS NULL",
        lease.consumer,
        lease.holder,
        epoch,
    )
    .execute(reader)
    .await?;
    Ok(())
}

/// Moves `lease.consumer`'s cursor forward to `at` only while `lease` is live; the check and the
/// write are one transaction that holds the lease row.
///
/// # Errors
/// [`StoreError::LeaseLost`] when the lease expired, was released or another holder took it;
/// [`StoreError`].
pub async fn ack_fenced(
    reader: &PgPool,
    lease: &CourierLease,
    at: Cursor,
) -> Result<(), StoreError> {
    let epoch = i64::try_from(lease.epoch).map_err(|_| StoreError::Range)?;
    let x = i64::try_from(at.xid).map_err(|_| StoreError::Range)?;
    let mut tx = reader.begin().await?;
    let held = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!" FROM access_ops.courier_leases
            WHERE consumer = $1 AND holder = $2 AND epoch = $3 AND released_at IS NULL
              AND expires_at > now()
            FOR UPDATE"#,
        lease.consumer,
        lease.holder,
        epoch,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if held.is_none() {
        return Err(StoreError::LeaseLost);
    }
    sqlx::query!(
        "INSERT INTO access_ops.outbox_cursor (consumer, xid, id) VALUES ($1, $2::bigint::text::xid8, $3)
         ON CONFLICT (consumer) DO UPDATE SET xid = EXCLUDED.xid, id = EXCLUDED.id, updated_at = now()
          WHERE (outbox_cursor.xid, outbox_cursor.id) < (EXCLUDED.xid, EXCLUDED.id)",
        lease.consumer,
        x,
        at.id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The age in ms of the oldest outbox event of a kind under `kind_prefix` past `after`, the
/// courier's lag; `None` when it has caught up.
///
/// # Errors
/// [`StoreError`].
pub async fn oldest_pending_ms(
    reader: &PgPool,
    after: Cursor,
    kind_prefix: &str,
) -> Result<Option<u64>, StoreError> {
    let after_xid = i64::try_from(after.xid).map_err(|_| StoreError::Range)?;
    let age = sqlx::query_scalar!(
        r#"SELECT (extract(epoch FROM clock_timestamp() - created_at) * 1000)::bigint AS "age_ms!"
             FROM access.identity_outbox
            WHERE (xid, id) > ($1::bigint::text::xid8, $2) AND left(kind, length($3)) = $3
            ORDER BY xid, id
            LIMIT 1"#,
        after_xid,
        after.id,
        kind_prefix,
    )
    .fetch_optional(reader)
    .await?;
    Ok(age.map(|a| u64::try_from(a).unwrap_or(0)))
}

/// An undeliverable message as a resend finds it: where it sits and why it was passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// Outbox kind.
    pub kind: String,
    /// Reason code.
    pub reason: String,
    /// The sealed outbox payload, when the row is still there.
    pub payload: Option<Vec<u8>>,
}

/// One resend: the new message's id beside the one it repeats.
pub struct Resend<'a> {
    /// The new `CloudEvents` id.
    pub event_id: [u8; 16],
    /// The undeliverable message it repeats.
    pub original_event_id: [u8; 16],
    /// Who asked.
    pub actor: &'a str,
    /// The request it came with.
    pub correlation: &'a str,
}

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

    /// The undeliverable message `event_id` of this realm and its sealed payload.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn relay_recorded(
        &mut self,
        event_id: [u8; 16],
    ) -> Result<Option<Recorded>, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let row = sqlx::query!(
            "SELECT u.kind, u.reason, o.payload AS \"payload?\"
               FROM access.relay_undelivered u
               LEFT JOIN access.identity_outbox o
                 ON o.tenant_id = u.tenant_id AND o.realm_id = u.realm_id
                AND o.id = u.outbox_id AND o.xid = u.outbox_xid
              WHERE u.tenant_id = $1 AND u.realm_id = $2 AND u.event_id = $3",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(event_id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| Recorded {
            kind: r.kind,
            reason: r.reason,
            payload: r.payload,
        }))
    }

    /// Records that `r.event_id` repeats `r.original_event_id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn relay_resend(&mut self, r: &Resend<'_>) -> Result<(), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.relay_resends
                (tenant_id, realm_id, event_id, original_event_id, actor, correlation)
             VALUES ($1, $2, $3, $4, $5, $6)",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(r.event_id),
            Uuid::from_bytes(r.original_event_id),
            r.actor,
            r.correlation,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The ids of the messages that repeat `original`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn relay_resends_of(
        &mut self,
        original: [u8; 16],
    ) -> Result<Vec<[u8; 16]>, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let rows = sqlx::query_scalar!(
            "SELECT event_id FROM access.relay_resends
              WHERE tenant_id = $1 AND realm_id = $2 AND original_event_id = $3
              ORDER BY recorded_at, event_id",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(original),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(Uuid::into_bytes).collect())
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
