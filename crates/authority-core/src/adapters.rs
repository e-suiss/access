//! PostgreSQL adapters of the core's ports (OP-63).

use access_store::Pool;
use access_store::authority::{NonceRow, find_nonce, state_of};
use access_store::scope::DomainId;
use suiss_crypto::dcbor::{self, Limits};

use crate::CoreError;
use crate::ports::{Reader, Row};

/// Reads one domain's state and nonces through the application role.
#[derive(Clone)]
pub struct PgReader {
    pool: Pool,
    domain: DomainId,
}

impl PgReader {
    /// A reader of `domain` over `pool`.
    #[must_use]
    pub const fn new(pool: Pool, domain: DomainId) -> Self {
        Self { pool, domain }
    }
}

impl Reader for PgReader {
    async fn fetch(&self, keys: &[Vec<u8>]) -> Result<Vec<Row>, CoreError> {
        let rows = state_of(&self.pool, &self.domain, keys).await?;
        keys.iter()
            .map(|k| match rows.iter().find(|r| &r.key == k) {
                None => Ok((k.clone(), None, 0)),
                Some(r) => {
                    let value = r
                        .value
                        .as_deref()
                        .map(|b| dcbor::decode(b, Limits::CEILING))
                        .transpose()
                        .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
                    Ok((k.clone(), value, r.version))
                }
            })
            .collect()
    }

    async fn nonce(&self, nonce: &[u8]) -> Result<Option<NonceRow>, CoreError> {
        Ok(find_nonce(&self.pool, &self.domain, nonce).await?)
    }
}
