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

/// An identity environment identifier. Deliberately without `Debug`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvironmentId(Uuid);

impl TenantId {
    /// From UUID bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(b))
    }

    /// The UUID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl EnvironmentId {
    /// From UUID bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(b))
    }

    /// The UUID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

/// A transaction scoped to one tenant and environment (OP-18).
pub struct TenantTx {
    pub(crate) tx: Transaction<'static, Postgres>,
    pub(crate) tenant: TenantId,
    environment: Option<EnvironmentId>,
}

impl TenantTx {
    /// Opens a transaction and sets `app.tenant_id` and `app.environment_id` for it only.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn begin(
        pool: &PgPool,
        tenant: TenantId,
        environment: EnvironmentId,
    ) -> Result<Self, StoreError> {
        let mut tx = pool.begin().await?;
        sqlx::query!(
            "SELECT set_config('app.tenant_id', $1, true) AS tenant, set_config('app.environment_id', $2, true) AS environment",
            tenant.0.to_string(),
            environment.0.to_string(),
        )
        .fetch_one(&mut *tx)
        .await?;
        Ok(Self {
            tx,
            tenant,
            environment: Some(environment),
        })
    }

    /// A transaction scoped to a tenant only: environment-scoped rows stay invisible.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn begin_tenant(pool: &PgPool, tenant: TenantId) -> Result<Self, StoreError> {
        let mut tx = pool.begin().await?;
        sqlx::query!(
            "SELECT set_config('app.tenant_id', $1, true) AS tenant",
            tenant.0.to_string()
        )
        .fetch_one(&mut *tx)
        .await?;
        Ok(Self {
            tx,
            tenant,
            environment: None,
        })
    }

    /// A transaction scoped to a tenant that reads the live stream subscriptions and webhooks of
    /// all its environments, as the fan-outs do (OP-132 m.5): every other environment-level row stays
    /// invisible, and no environment-level row can be written in it.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn begin_tenant_wide(pool: &PgPool, tenant: TenantId) -> Result<Self, StoreError> {
        let mut tx = pool.begin().await?;
        sqlx::query!(
            "SELECT set_config('app.tenant_id', $1, true) AS tenant, set_config('app.environment_wide', 'on', true) AS wide",
            tenant.0.to_string()
        )
        .fetch_one(&mut *tx)
        .await?;
        Ok(Self {
            tx,
            tenant,
            environment: None,
        })
    }

    /// Narrows a tenant-only transaction to `environment`, for the rows an environment's creation writes
    /// after its own (TN-111).
    ///
    /// # Errors
    /// [`StoreError::Range`] when the transaction already has an environment; [`StoreError::Db`].
    pub async fn enter_environment(
        &mut self,
        environment: EnvironmentId,
    ) -> Result<(), StoreError> {
        if self.environment.is_some() {
            return Err(StoreError::Range);
        }
        sqlx::query!(
            "SELECT set_config('app.environment_id', $1, true) AS environment",
            environment.0.to_string(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        self.environment = Some(environment);
        Ok(())
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The environment, when the scope has one.
    #[must_use]
    pub const fn environment(&self) -> Option<EnvironmentId> {
        self.environment
    }

    /// The database server's clock, Unix milliseconds (OP-129 m.1).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn server_time(&mut self) -> Result<u64, StoreError> {
        let ms = sqlx::query_scalar!(
            r#"SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint AS "ms!""#
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64::try_from(ms).map_err(|_| StoreError::Corrupt)
    }

    /// Adds an event to the outbox in this transaction (OP-10).
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn outbox(&mut self, kind: &str, payload: &[u8]) -> Result<(), StoreError> {
        self.outbox_traced(kind, payload, None).await
    }

    /// Adds an event to the outbox in this transaction with the writing request's
    /// `traceparent` (OP-10, OP-67 m.1).
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn outbox_traced(
        &mut self,
        kind: &str,
        payload: &[u8],
        trace_parent: Option<&str>,
    ) -> Result<(), StoreError> {
        let environment = self.environment.ok_or(StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.identity_outbox (tenant_id, environment_id, kind, payload, trace_parent)
             VALUES ($1, $2, $3, $4, $5)",
            self.tenant.0,
            environment.0,
            kind,
            payload,
            trace_parent,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Runs a query in this scope; for the isolation tests only.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    #[cfg(feature = "testing")]
    pub async fn raw_rows(mut self, sql: &str) -> Result<Vec<sqlx::postgres::PgRow>, StoreError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_all(&mut *self.tx)
            .await?;
        self.tx.commit().await?;
        Ok(rows)
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
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxEvent {
    /// The tenant that wrote it.
    pub tenant: TenantId,
    /// The environment that wrote it.
    pub environment: EnvironmentId,
    /// Writing transaction id (xid8).
    pub xid: u64,
    /// Row id, the order within one transaction.
    pub id: i64,
    /// Event kind.
    pub kind: String,
    /// Payload.
    pub payload: Vec<u8>,
    /// The writing request's `traceparent`, if it had one (OP-67 m.1).
    pub trace_parent: Option<String>,
    /// Milliseconds since it was written, by the database clock (§17.8.2 outbox lag).
    pub age_ms: u64,
}

/// Where a consumer stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor {
    /// Transaction id of the last acknowledged event.
    pub xid: u64,
    /// Its row id.
    pub id: i64,
}

impl core::fmt::Debug for OutboxEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboxEvent")
            .field("xid", &self.xid)
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
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
        r#"SELECT tenant_id, environment_id, xid::text::bigint AS "xid!", id, kind, payload, trace_parent,
                  (extract(epoch FROM clock_timestamp() - created_at) * 1000)::bigint AS "age_ms!"
             FROM access.identity_outbox
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
                tenant: TenantId(r.tenant_id),
                environment: EnvironmentId(r.environment_id),
                xid: xid(Some(r.xid))?,
                id: r.id,
                kind: r.kind,
                payload: r.payload,
                trace_parent: r.trace_parent,
                age_ms: u64::try_from(r.age_ms).unwrap_or(0),
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
