//! The executor's own SQL module (OP-154 m.3 (u), OP-66 for this service): its job history in
//! the `executor` schema of its own database. Rows are only ever inserted (OP-73).

use sqlx::PgPool;
use sqlx::migrate::Migrator;

/// The executor's migrations, `services/executor/migrations`.
pub static MIGRATOR: Migrator = sqlx::migrate!();

/// A store failure: the job waits, nothing is assumed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused or was unreachable.
    #[error("executor store: {0}")]
    Db(#[from] sqlx::Error),
    /// The migrations failed.
    #[error("executor migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A stored value is out of shape.
    #[error("executor store: corrupt row")]
    Corrupt,
    /// Concurrent appends kept taking the next position.
    #[error("executor store: contended")]
    Contended,
}

/// The job store.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
}

fn id16(b: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

impl Store {
    /// The store over `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connects to the executor database at `url`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        Ok(Self::new(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .connect(url)
                .await?,
        ))
    }

    /// Applies the migrations.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn migrate(&self) -> Result<(), StoreError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// Opens the job of `exercise` with its first event, or answers the job that already runs
    /// it (one job per Exercise).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn create(
        &self,
        job: [u8; 16],
        (domain, exercise): ([u8; 32], [u8; 32]),
        kind: &str,
        first: &str,
    ) -> Result<([u8; 16], bool), StoreError> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query!(
            "INSERT INTO executor.jobs (job, domain_id, exercise, kind) VALUES ($1, $2, $3, $4)
             ON CONFLICT (domain_id, exercise) DO NOTHING",
            &job[..],
            &domain[..],
            &exercise[..],
            kind,
        )
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if !inserted {
            let row = sqlx::query!(
                "SELECT job FROM executor.jobs WHERE domain_id = $1 AND exercise = $2",
                &domain[..],
                &exercise[..],
            )
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok((id16(&row.job)?, false));
        }
        sqlx::query!(
            "INSERT INTO executor.events (job, seq, event) VALUES ($1, 0, $2)",
            &job[..],
            first,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((job, true))
    }

    /// Appends `event` at `seq`; `false` when that position is taken, so the caller's view is
    /// stale and nothing it decided on it may happen (TI-6).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn append_at(
        &self,
        job: [u8; 16],
        seq: i32,
        event: &str,
    ) -> Result<bool, StoreError> {
        Ok(sqlx::query!(
            "INSERT INTO executor.events (job, seq, event) VALUES ($1, $2, $3)
             ON CONFLICT (job, seq) DO NOTHING",
            &job[..],
            seq,
            event,
        )
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1)
    }

    /// Appends `event` at the next free position: a fact that is recorded whatever came
    /// before it (an answer, a control request).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn append(&self, job: [u8; 16], event: &str) -> Result<i32, StoreError> {
        for _ in 0..16 {
            let row = sqlx::query!(
                "INSERT INTO executor.events (job, seq, event)
                 SELECT $1, COALESCE(MAX(seq), -1) + 1, $2 FROM executor.events WHERE job = $1
                 ON CONFLICT (job, seq) DO NOTHING
                 RETURNING seq",
                &job[..],
                event,
            )
            .fetch_optional(&self.pool)
            .await?;
            if let Some(r) = row {
                return Ok(r.seq);
            }
        }
        Err(StoreError::Contended)
    }

    /// The job's events, in order; empty for an unknown job.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn history(&self, job: [u8; 16]) -> Result<Vec<String>, StoreError> {
        Ok(sqlx::query!(
            "SELECT event FROM executor.events WHERE job = $1 ORDER BY seq",
            &job[..],
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| r.event)
        .collect())
    }

    /// The newest jobs, at most `limit`, to pick up after a restart.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn jobs(&self, limit: i64) -> Result<Vec<[u8; 16]>, StoreError> {
        sqlx::query!(
            "SELECT job FROM executor.jobs ORDER BY created_at DESC, job LIMIT $1",
            limit,
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| id16(&r.job))
        .collect()
    }
}
