//! The verifier's own SQL module (OP-155 m.3 (p), OP-66 for this service): requests, their one
//! outcome and the trusted list snapshots in the `vc_verifier` schema of its own database. Rows
//! are only ever inserted (OP-73).

use sqlx::PgPool;
use sqlx::migrate::Migrator;

/// The verifier's migrations, `services/vc-verifier/migrations`.
pub static MIGRATOR: Migrator = sqlx::migrate!();

/// A store failure: nothing is assumed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused or was unreachable.
    #[error("verifier store: {0}")]
    Db(#[from] sqlx::Error),
    /// The migrations failed.
    #[error("verifier migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A stored value is out of shape.
    #[error("verifier store: corrupt row")]
    Corrupt,
}

/// A stored request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRow {
    /// The request id.
    pub request: [u8; 16],
    /// SHA-256 of the caller's key.
    pub caller: [u8; 32],
    /// The domain.
    pub domain: [u8; 32],
    /// The subject Party.
    pub subject: [u8; 16],
    /// `same-device` or `cross-device`.
    pub mode: String,
    /// The DCQL query as JSON.
    pub query: String,
    /// The nonce.
    pub nonce: String,
    /// The state.
    pub state: String,
    /// Where a same-device wallet returns.
    pub return_uri: Option<String>,
    /// Opened at, milliseconds.
    pub created_ms: u64,
    /// Expires at, milliseconds.
    pub expires_ms: u64,
}

/// A stored outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeRow {
    /// `verified` or `refused`.
    pub outcome: String,
    /// The refusal's code.
    pub reason: Option<String>,
    /// The outcome's detail as JSON (never a disclosed value).
    pub detail: String,
    /// SHA-256 of the same-device response code.
    pub response_code: Option<[u8; 32]>,
    /// Recorded at, milliseconds.
    pub recorded_ms: u64,
}

/// The verifier store.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
}

fn fixed<const N: usize>(b: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

fn ms(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn db_ms(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt)
}

impl Store {
    /// The store over `pool`.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connects to the verifier database at `url`.
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

    /// Opens a request.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open(&self, r: &RequestRow) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO vc_verifier.requests
               (request, caller, domain_id, subject, mode, query, nonce, state, return_uri,
                created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &r.request[..],
            &r.caller[..],
            &r.domain[..],
            &r.subject[..],
            r.mode,
            r.query,
            r.nonce,
            r.state,
            r.return_uri,
            db_ms(r.created_ms)?,
            db_ms(r.expires_ms)?,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A request and its outcome, if any.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn get(
        &self,
        request: &[u8; 16],
    ) -> Result<Option<(RequestRow, Option<OutcomeRow>)>, StoreError> {
        let Some(row) = sqlx::query!(
            "SELECT r.request, r.caller, r.domain_id, r.subject, r.mode, r.query, r.nonce, r.state,
                    r.return_uri, r.created_ms, r.expires_ms,
                    o.outcome AS \"outcome?\", o.reason, o.detail AS \"detail?\",
                    o.response_code, o.recorded_ms AS \"recorded_ms?\"
               FROM vc_verifier.requests r
               LEFT JOIN vc_verifier.outcomes o ON o.request = r.request
              WHERE r.request = $1",
            &request[..],
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let req = RequestRow {
            request: fixed(&row.request)?,
            caller: fixed(&row.caller)?,
            domain: fixed(&row.domain_id)?,
            subject: fixed(&row.subject)?,
            mode: row.mode,
            query: row.query,
            nonce: row.nonce,
            state: row.state,
            return_uri: row.return_uri,
            created_ms: ms(row.created_ms)?,
            expires_ms: ms(row.expires_ms)?,
        };
        let outcome = match (row.outcome, row.detail, row.recorded_ms) {
            (Some(outcome), Some(detail), Some(recorded)) => Some(OutcomeRow {
                outcome,
                reason: row.reason,
                detail,
                response_code: row.response_code.as_deref().map(fixed).transpose()?,
                recorded_ms: ms(recorded)?,
            }),
            (None, None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Some((req, outcome)))
    }

    /// Records a request's one outcome; `false` when it already has one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record(&self, request: &[u8; 16], o: &OutcomeRow) -> Result<bool, StoreError> {
        let done = sqlx::query!(
            "INSERT INTO vc_verifier.outcomes
               (request, outcome, reason, detail, response_code, recorded_ms)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (request) DO NOTHING",
            &request[..],
            o.outcome,
            o.reason,
            o.detail,
            o.response_code.as_ref().map(|c| &c[..]),
            db_ms(o.recorded_ms)?,
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Appends a trusted list snapshot.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_lists(&self, loaded_ms: u64, snapshot: &str) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO vc_verifier.trusted_lists (loaded_ms, snapshot) VALUES ($1, $2)
             ON CONFLICT (loaded_ms) DO NOTHING",
            db_ms(loaded_ms)?,
            snapshot,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The latest trusted list snapshot.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn latest_lists(&self) -> Result<Option<String>, StoreError> {
        Ok(sqlx::query_scalar!(
            "SELECT snapshot FROM vc_verifier.trusted_lists ORDER BY loaded_ms DESC LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await?)
    }
}
