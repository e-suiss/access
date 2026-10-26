//! Opening the database safely (OP-52, OP-53, OP-130 m.10, OP-131 m.4): TLS with full
//! verification against an explicit root, SCRAM only, PostgreSQL 18 or later, bounded
//! transactions, and one pool per role whose sizes fit the server.

use std::path::Path;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

use crate::StoreError;

/// Oldest server major version accepted (OP-7).
pub const MIN_SERVER_VERSION: i32 = 180_000;

/// Longest transaction of an application role (OP-131 m.4, PD).
pub const TRANSACTION_TIMEOUT: &str = "30s";

/// Longest idle-in-transaction pause (OP-131 m.4, PD).
pub const IDLE_IN_TRANSACTION_TIMEOUT: &str = "10s";

/// Share of `max_connections` the pools may take together (OP-53).
pub const POOL_SHARE_PERCENT: u32 = 70;

/// Where and as whom to connect.
pub struct Target<'a> {
    /// Server host name, checked against its certificate.
    pub host: &'a str,
    /// Port.
    pub port: u16,
    /// Database.
    pub database: &'a str,
    /// Login role.
    pub user: &'a str,
    /// Its password, read from a credential file by the caller.
    pub password: &'a str,
    /// PEM file of the root the server certificate must chain to.
    pub root_cert: &'a Path,
}

/// Why the database is not safe to use; the process does not start (OP-52).
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The server refused or the query failed.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// Server older than PostgreSQL 18.
    #[error("server version {0} is older than PostgreSQL 18")]
    Version(i32),
    /// Passwords are not stored as SCRAM.
    #[error("password_encryption is {0}, not scram-sha-256")]
    Scram(String),
    /// The connection is not encrypted.
    #[error("the connection does not use TLS")]
    NoTls,
    /// A commit may be acknowledged before it is durable (U51, OP-24).
    #[error(
        "synchronous_commit is {commit} with standbys {standbys:?}; commits must wait for durability"
    )]
    Durability {
        /// `synchronous_commit`.
        commit: String,
        /// `synchronous_standby_names`.
        standbys: String,
    },
    /// The pools would take more than their share of `max_connections`.
    #[error(
        "pools need {need} connections, more than {POOL_SHARE_PERCENT}% of max_connections ({max})"
    )]
    PoolSize {
        /// Connections the pools need.
        need: u32,
        /// `max_connections`.
        max: u32,
    },
}

/// Connection options: `verify-full` against `root_cert`, the timeouts as startup parameters.
#[must_use]
pub fn options(t: &Target<'_>) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(t.host)
        .port(t.port)
        .database(t.database)
        .username(t.user)
        .password(t.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(t.root_cert)
        .application_name("access")
        .options([
            ("transaction_timeout", TRANSACTION_TIMEOUT),
            (
                "idle_in_transaction_session_timeout",
                IDLE_IN_TRANSACTION_TIMEOUT,
            ),
        ])
}

/// A pool of `size` connections with a short acquire timeout; the queue lives in the
/// application (OP-53).
///
/// # Errors
/// [`ConnectError::Db`].
pub async fn pool(opts: PgConnectOptions, size: u32) -> Result<PgPool, ConnectError> {
    Ok(PgPoolOptions::new()
        .max_connections(size)
        .min_connections(size.min(2))
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(opts)
        .await?)
}

/// Whether a `server_version_num` is supported.
#[must_use]
pub const fn supported(version: i32) -> bool {
    version >= MIN_SERVER_VERSION
}

/// Whether `pools` connections fit `max_connections`.
#[must_use]
pub const fn fits(pools: u32, max_connections: u32) -> bool {
    (pools as u64).saturating_mul(100)
        <= (max_connections as u64).saturating_mul(POOL_SHARE_PERCENT as u64)
}

/// How the deployment declares its durability (OP-24, OP-48).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Synchronous standbys required (`synchronous_standby_names` set).
    Replicated,
    /// The small-provider `durability: single-node` declaration (HL-40).
    SingleNode,
}

/// Checks the server before the process serves anything (OP-52): version, SCRAM, TLS on this
/// connection, durable commits as declared, and room for `pools` connections.
///
/// # Errors
/// [`ConnectError`].
pub async fn check_server(
    pool: &PgPool,
    pools: u32,
    require_tls: bool,
    durability: Durability,
) -> Result<(), StoreError> {
    let row = sqlx::query!(
        r#"SELECT current_setting('server_version_num')::int AS "version!",
                  current_setting('password_encryption') AS "scram!",
                  current_setting('max_connections')::int AS "max!",
                  coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS "tls!",
                  current_setting('synchronous_commit') AS "commit!",
                  current_setting('synchronous_standby_names') AS "standbys!""#
    )
    .fetch_one(pool)
    .await?;
    let fail = |e: ConnectError| StoreError::Unsafe(e.to_string());
    if !supported(row.version) {
        return Err(fail(ConnectError::Version(row.version)));
    }
    if row.scram != "scram-sha-256" {
        return Err(fail(ConnectError::Scram(row.scram)));
    }
    if require_tls && !row.tls {
        return Err(fail(ConnectError::NoTls));
    }
    // U51, OP-24: `on` waits for the standbys named; `local` or `off` acknowledge early
    let standbys_ok = durability == Durability::SingleNode || !row.standbys.trim().is_empty();
    if !matches!(row.commit.as_str(), "on" | "remote_apply") || !standbys_ok {
        return Err(fail(ConnectError::Durability {
            commit: row.commit,
            standbys: row.standbys,
        }));
    }
    let max = u32::try_from(row.max).map_err(|_| StoreError::Corrupt)?;
    if !fits(pools, max) {
        return Err(fail(ConnectError::PoolSize { need: pools, max }));
    }
    Ok(())
}

/// Runs the migrations as a member of `access_migrator`, from the separate migration job and
/// never at application start (OP-55).
///
/// # Errors
/// [`StoreError`].
pub async fn migrate(migrator: &PgPool) -> Result<(), StoreError> {
    crate::MIGRATOR
        .run(migrator)
        .await
        .map_err(|e| StoreError::Unsafe(e.to_string()))
}
