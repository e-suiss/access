//! Typed scope (TN-22, OP-18, OP-130 m.3): a transaction carries its domain scope from `BEGIN`,
//! set with `set_config(…, true)`, so a statement cannot run unscoped.

use sqlx::{PgPool, Postgres, Transaction};

use crate::StoreError;

/// An `AuthorityDomain` identifier: the 32-byte genesis digest. Deliberately without `Debug`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainId([u8; 32]);

impl DomainId {
    /// From the raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.extend([b >> 4, b & 0x0f].map(|n| char::from_digit(u32::from(n), 16).unwrap_or('0')));
        }
        s
    }
}

/// A transaction scoped to one domain.
pub struct DomainTx {
    pub(crate) tx: Transaction<'static, Postgres>,
    pub(crate) domain: DomainId,
}

impl DomainTx {
    /// Opens a transaction and sets `app.domain_id` for it only.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn begin(pool: &PgPool, domain: &DomainId) -> Result<Self, StoreError> {
        let mut tx = pool.begin().await?;
        sqlx::query!("SELECT set_config('app.domain_id', $1, true)", domain.hex())
            .fetch_one(&mut *tx)
            .await?;
        Ok(Self {
            tx,
            domain: *domain,
        })
    }

    /// The scope.
    #[must_use]
    pub const fn domain(&self) -> &DomainId {
        &self.domain
    }

    /// Commits.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().await?;
        Ok(())
    }
}
