//! Identity plane scope and outbox (OP-12, OP-20, OP-131).
//!
//! Events are written in the business transaction. A reader takes only rows whose transaction
//! id is below the oldest running one, so a transaction that started earlier but commits later
//! is waited for, never skipped (OQ-MD3, OPI-1).

use sqlx::types::Uuid;
use sqlx::{PgPool, Postgres, Transaction};

use crate::StoreError;

/// A tenant identifier. Deliberately without `Debug`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

/// An identity realm identifier. Deliberately without `Debug`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RealmId(Uuid);

impl TenantId {
    /// From UUID bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(b))
    }
}

impl RealmId {
    /// From UUID bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(b))
    }
}

/// A transaction scoped to one tenant and realm (OP-18).
pub struct TenantTx {
    tx: Transaction<'static, Postgres>,
    tenant: TenantId,
    realm: RealmId,
}

impl TenantTx {
    /// Opens a transaction and sets `app.tenant_id` and `app.realm_id` for it only.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn begin(
        pool: &PgPool,
        tenant: TenantId,
        realm: RealmId,
    ) -> Result<Self, StoreError> {
        let mut tx = pool.begin().await?;
        sqlx::query!(
            "SELECT set_config('app.tenant_id', $1, true) AS tenant, set_config('app.realm_id', $2, true) AS realm",
            tenant.0.to_string(),
            realm.0.to_string(),
        )
        .fetch_one(&mut *tx)
        .await?;
        Ok(Self { tx, tenant, realm })
    }

    /// Adds an event to the outbox in this transaction (OP-10).
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn outbox(&mut self, kind: &str, payload: &[u8]) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO access.identity_outbox (tenant_id, realm_id, kind, payload) VALUES ($1, $2, $3, $4)",
            self.tenant.0,
            self.realm.0,
            kind,
            payload,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Commits.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().await?;
        Ok(())
    }

    /// Rolls back.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn rollback(self) -> Result<(), StoreError> {
        self.tx.rollback().await?;
        Ok(())
    }
}

/// One delivered outbox event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxEvent {
    /// Writing transaction id (xid8).
    pub xid: u64,
    /// Row id, the order within one transaction.
    pub id: i64,
    /// Event kind.
    pub kind: String,
    /// Payload.
    pub payload: Vec<u8>,
}

/// Where a consumer stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor {
    /// Transaction id of the last acknowledged event.
    pub xid: u64,
    /// Its row id.
    pub id: i64,
}

impl OutboxEvent {
    /// The cursor just after this event.
    #[must_use]
    pub const fn cursor(&self) -> Cursor {
        Cursor {
            xid: self.xid,
            id: self.id,
        }
    }
}

fn xid(v: Option<i64>) -> Result<u64, StoreError> {
    v.and_then(|x| u64::try_from(x).ok())
        .ok_or(StoreError::Corrupt)
}

/// The stored cursor of `consumer`; the start of the outbox when it has none.
///
/// # Errors
/// [`StoreError`].
pub async fn cursor(reader: &PgPool, consumer: &str) -> Result<Cursor, StoreError> {
    let row = sqlx::query!(
        r#"SELECT xid::text::bigint AS "xid!", id FROM access_ops.outbox_cursor WHERE consumer = $1"#,
        consumer,
    )
    .fetch_optional(reader)
    .await?;
    row.map_or(Ok(Cursor::default()), |r| {
        xid(Some(r.xid)).map(|x| Cursor { xid: x, id: r.id })
    })
}

/// Events after `after`, in delivery order, up to `limit`. Only transactions that have ended are
/// read: every transaction id below the snapshot's `xmin` has committed or aborted.
///
/// # Errors
/// [`StoreError`].
pub async fn poll(
    reader: &PgPool,
    after: Cursor,
    limit: u32,
) -> Result<Vec<OutboxEvent>, StoreError> {
    let after_xid = i64::try_from(after.xid).map_err(|_| StoreError::Range)?;
    let rows = sqlx::query!(
        r#"SELECT xid::text::bigint AS "xid!", id, kind, payload FROM access.identity_outbox
            WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
              AND (xid, id) > ($1::bigint::text::xid8, $2)
            ORDER BY xid, id
            LIMIT $3"#,
        after_xid,
        after.id,
        i64::from(limit),
    )
    .fetch_all(reader)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(OutboxEvent {
                xid: xid(Some(r.xid))?,
                id: r.id,
                kind: r.kind,
                payload: r.payload,
            })
        })
        .collect()
}

/// Stores `consumer`'s cursor after the events it has handled; never moves it back.
///
/// # Errors
/// [`StoreError`].
pub async fn ack(reader: &PgPool, consumer: &str, at: Cursor) -> Result<(), StoreError> {
    let x = i64::try_from(at.xid).map_err(|_| StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access_ops.outbox_cursor (consumer, xid, id) VALUES ($1, $2::bigint::text::xid8, $3)
         ON CONFLICT (consumer) DO UPDATE SET xid = EXCLUDED.xid, id = EXCLUDED.id, updated_at = now()
          WHERE (outbox_cursor.xid, outbox_cursor.id) < (EXCLUDED.xid, EXCLUDED.id)",
        consumer,
        x,
        at.id,
    )
    .execute(reader)
    .await?;
    Ok(())
}
