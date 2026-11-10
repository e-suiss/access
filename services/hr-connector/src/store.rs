//! The HR connector's own SQL module (OP-156 m.3 (q), OP-66 for this service): its run history
//! in the `hr_connector` schema of its own database. Rows are only ever inserted (OP-73).

use sqlx::PgPool;
use sqlx::migrate::Migrator;

use crate::app::Report;

/// The connector's migrations, `services/hr-connector/migrations`.
pub static MIGRATOR: Migrator = sqlx::migrate!();

/// A store failure: the run is not recorded, nothing is assumed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused or was unreachable.
    #[error("hr connector store: {0}")]
    Db(#[from] sqlx::Error),
    /// The migrations failed.
    #[error("hr connector migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A stored value is out of shape.
    #[error("hr connector store: corrupt row")]
    Corrupt,
}

/// One recorded run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// Its id.
    pub run: [u8; 16],
    /// The connector.
    pub connector: String,
    /// Unix ms.
    pub started_ms: u64,
    /// Unix ms.
    pub ended_ms: u64,
    /// `done` or `failed`.
    pub outcome: String,
    /// Its counts.
    pub report: Report,
    /// Why it failed, by stable word.
    pub reason: Option<String>,
}

fn count(n: i32) -> Result<u32, StoreError> {
    u32::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn signed(n: u32) -> Result<i32, StoreError> {
    i32::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn ms(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// The run store.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// The store over `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connects to the connector database at `url`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        Ok(Self::new(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(4)
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

    /// Whether the database answers.
    pub async fn healthy(&self) -> bool {
        sqlx::query_scalar!("SELECT 1 AS \"one!\"")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    /// Records the run `r`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record(&self, r: &Run) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO hr_connector.runs (run, connector, started_ms, ended_ms, outcome, read,
                    left_out, pushed, refused, batches, reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            r.run.as_slice(),
            r.connector,
            i64::try_from(r.started_ms).map_err(|_| StoreError::Corrupt)?,
            i64::try_from(r.ended_ms).map_err(|_| StoreError::Corrupt)?,
            r.outcome,
            signed(r.report.read)?,
            signed(r.report.left_out)?,
            signed(r.report.pushed)?,
            signed(r.report.refused)?,
            signed(r.report.batches)?,
            r.reason,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The newest `limit` runs of `connector`, newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn runs(&self, connector: &str, limit: u32) -> Result<Vec<Run>, StoreError> {
        let rows = sqlx::query!(
            "SELECT run, connector, started_ms, ended_ms, outcome, read, left_out, pushed,
                    refused, batches, reason
               FROM hr_connector.runs WHERE connector = $1
              ORDER BY ended_ms DESC, recorded_at DESC LIMIT $2",
            connector,
            i64::from(limit),
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(Run {
                    run: <[u8; 16]>::try_from(r.run.as_slice()).map_err(|_| StoreError::Corrupt)?,
                    connector: r.connector,
                    started_ms: ms(r.started_ms)?,
                    ended_ms: ms(r.ended_ms)?,
                    outcome: r.outcome,
                    report: Report {
                        read: count(r.read)?,
                        left_out: count(r.left_out)?,
                        pushed: count(r.pushed)?,
                        refused: count(r.refused)?,
                        batches: count(r.batches)?,
                    },
                    reason: r.reason,
                })
            })
            .collect()
    }

    /// The run `run`, if recorded.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn run(&self, connector: &str, run: [u8; 16]) -> Result<Option<Run>, StoreError> {
        Ok(self
            .runs(connector, 1000)
            .await?
            .into_iter()
            .find(|r| r.run == run))
    }
}
