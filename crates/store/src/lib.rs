//! PostgreSQL access for Access (OP-66, OP-130): migrations, row-level security and typed scope.
//! All SQL of the workspace lives in this crate.

pub mod authority;

/// The connection pool type, so other crates need no driver dependency (OP-66 m.2).
pub use sqlx::PgPool as Pool;

pub mod identity;
pub mod jobs;
pub mod scope;

#[cfg(feature = "testing")]
pub mod testing;

/// The embedded migrations; run by the separate migration job, never at application start (OP-55).
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Cluster roles, created once by the database administrator (OP-130 m.2).
pub const BOOTSTRAP_ROLES: &str = include_str!("../bootstrap/roles.sql");

/// Per-database setup run by the database administrator before the first migration.
pub const BOOTSTRAP_DATABASE: &str = include_str!("../bootstrap/database.sql");

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database rejected or could not run the statement.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// The stored head moved or the epoch changed: another writer won (OP-130 m.6).
    #[error("head compare-and-set lost")]
    HeadMoved,
    /// The domain's sequencer lease is held by another holder.
    #[error("sequencer lease held elsewhere")]
    LeaseHeld,
    /// The lease is no longer ours.
    #[error("sequencer lease lost")]
    LeaseLost,
    /// A value does not fit its column.
    #[error("value out of range")]
    Range,
    /// A stored row does not match the model.
    #[error("stored row is malformed")]
    Corrupt,
}
