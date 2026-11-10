//! Throwaway HR connector databases for tests: one migrated clone per test on the cluster
//! `DATABASE_URL` names, named like the store's clones so its sweep removes the idle ones.

use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection as _, Executor as _, PgConnection, PgPool};

use crate::store::{Store, StoreError};

fn name() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "access_t_{}_{}_{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A fresh, migrated HR connector database and its store.
///
/// # Errors
/// [`StoreError`]; a missing `DATABASE_URL` is [`StoreError::Corrupt`].
pub async fn store() -> Result<(Store, PgPool), StoreError> {
    let url = std::env::var("DATABASE_URL").map_err(|_| StoreError::Corrupt)?;
    let admin = PgConnectOptions::from_str(&url)?;
    let db = name();
    let mut c = PgConnection::connect_with(&admin).await?;
    c.execute(AssertSqlSafe(format!("CREATE DATABASE {db}")))
        .await?;
    c.close().await?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(admin.database(&db))
        .await?;
    let store = Store::new(pool.clone());
    store.migrate().await?;
    Ok((store, pool))
}
