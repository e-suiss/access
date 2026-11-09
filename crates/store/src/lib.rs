//! PostgreSQL access for Access (OP-66, OP-130): migrations, row-level security and typed scope.
//! All SQL of the workspace lives in this crate.

pub mod accounts;
pub mod admin_jobs;
pub mod agents;
pub mod analytics;
pub mod api_idempotency;
pub mod approvals;
pub mod audit;
pub mod audit_lease;
pub mod audit_realm;
pub mod authority;
pub mod authority_checkpoint;
pub mod backchannel;
pub mod bodies;
pub mod challenges;
pub mod claims;
pub mod clients;
pub mod connect;
pub mod consents;
pub mod console;
pub mod cross_app;
pub mod dcr;
pub mod derived;
pub mod device;
pub mod dpop;
pub mod edge;
pub mod ephemeral;
pub mod events;
pub mod extensions;
pub mod federation;

/// The connection pool type, so other crates need no driver dependency (OP-66 m.2).
pub use sqlx::PgPool as Pool;

pub mod identity;
pub mod idp;
pub mod issuer;
pub mod jobs;
pub mod locks;
pub mod oauth;
pub mod offline;
pub mod operational;
pub mod org_authority;
pub mod orgs;
pub mod passkeys;
pub mod platform;
pub mod privacy;
pub mod projections;
pub mod publications;
pub mod realm_binding;
pub mod recovery;
pub mod relay;
pub mod risk;
pub mod sandbox;
pub mod scope;
pub mod sessions;
pub mod ssf;
pub mod status;
pub mod tenancy;
pub mod throttle;
pub mod vault;
pub mod workloads;

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
    /// A key the batch read changed since it was read (TI-4); re-evaluate.
    #[error("read set changed")]
    Stale,
    /// A counter would go past its limit (§17.1.1 step 9); re-evaluate.
    #[error("counter exhausted")]
    Exhausted,
    /// A single-use flag is already set.
    #[error("already consumed")]
    Consumed,
    /// A stored row does not match the model.
    #[error("stored row is malformed")]
    Corrupt,
    /// The database is not safe to use (OP-52); the process must not start.
    #[error("unsafe database: {0}")]
    Unsafe(String),
}

impl StoreError {
    /// Whether the database refused the write for the state it found: an integrity constraint,
    /// a foreign key or a trigger raising one (SQLSTATE class 23). The write did not happen; it
    /// is a conflict with the current state, not an outage.
    #[must_use]
    pub fn integrity(&self) -> bool {
        matches!(self, Self::Db(sqlx::Error::Database(e))
            if e.code().is_some_and(|c| c.starts_with("23")))
    }
}
