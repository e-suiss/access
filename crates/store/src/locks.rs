//! Cell-wide locks (OP-149 m.22 (g)): processes of one cell share its database, so a
//! transaction-scoped advisory lock serialises work outside the database that has no uniqueness
//! of its own, such as making a key under a token label.

use sqlx::{PgPool, Postgres, Transaction};

use crate::StoreError;

/// A held cell-wide lock; released by [`CellLock::release`] or when dropped.
pub struct CellLock(Transaction<'static, Postgres>);

/// Waits for the cell-wide lock named `name`.
///
/// # Errors
/// [`StoreError`].
pub async fn cell_lock(pool: &PgPool, name: &str) -> Result<CellLock, StoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query!(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        name
    )
    .execute(&mut *tx)
    .await?;
    Ok(CellLock(tx))
}

impl CellLock {
    /// Releases the lock.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn release(self) -> Result<(), StoreError> {
        self.0.commit().await?;
        Ok(())
    }
}
