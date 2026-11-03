//! The three-tier `session_epoch` check of one realm (MD-7, OP-21, §17.3.4): the node cache,
//! the poll of moved epochs, and the primary. Never-seen subjects ask the primary; a primary
//! that cannot answer is an error and the caller denies (G49, MD-8).

use std::sync::{Mutex, PoisonError};

use access_identity_account::ports::AccountTx;
use access_store::identity::{RealmId, TenantId};

use crate::SessionError;
use crate::domain::epoch::{EpochCache, EpochCheck};
use crate::ports::{SessionDb, SessionTx};

/// How far back a poll re-reads, for transactions that commit out of timestamp order.
pub const POLL_OVERLAP_MS: i64 = 5_000;

/// Rows one poll reads at most.
pub const POLL_LIMIT: i64 = 10_000;

/// The epoch tiers of one realm on one node.
pub struct Epochs {
    tenant: TenantId,
    realm: RealmId,
    cache: Mutex<EpochCache>,
}

fn poisoned<T>(_: PoisonError<T>) -> SessionError {
    SessionError::Corrupt
}

impl Epochs {
    /// The tiers of a realm; cache hits are trusted for `max_staleness_ms`.
    #[must_use]
    pub fn new(tenant: TenantId, realm: RealmId, max_staleness_ms: u64) -> Self {
        Self {
            tenant,
            realm,
            cache: Mutex::new(EpochCache::new(max_staleness_ms)),
        }
    }

    /// Whether `presented` is the subject's current epoch at `now_ms`. An unknown subject is
    /// never current.
    ///
    /// # Errors
    /// [`SessionError`] when the primary cannot answer: the caller denies.
    pub async fn current<D: SessionDb>(
        &self,
        db: &D,
        subject: [u8; 16],
        presented: i64,
        now_ms: u64,
    ) -> Result<bool, SessionError> {
        let cached = self
            .cache
            .lock()
            .map_err(poisoned)?
            .check(&subject, presented, now_ms);
        match cached {
            EpochCheck::Current => return Ok(true),
            EpochCheck::Revoked => return Ok(false),
            EpochCheck::AskPrimary => {}
        }
        let mut tx = db.begin(self.tenant, self.realm).await?;
        let row = tx.subject(subject, false).await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(false);
        };
        self.cache
            .lock()
            .map_err(poisoned)?
            .observe(subject, row.session_epoch, now_ms);
        Ok(row.session_epoch == presented)
    }

    /// One poll: reads epochs that moved since the cursor (with overlap) and applies them.
    /// At start-up the first poll from `since_ms` loads the recent revocation set in one
    /// query (OP-21). Returns how many moved.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn poll<D: SessionDb>(
        &self,
        db: &D,
        since_ms: Option<i64>,
        now_ms: u64,
    ) -> Result<usize, SessionError> {
        let from = match since_ms {
            Some(s) => s,
            None => self
                .cache
                .lock()
                .map_err(poisoned)?
                .cursor_ms()
                .saturating_sub(POLL_OVERLAP_MS),
        };
        let mut tx = db.begin(self.tenant, self.realm).await?;
        let moved = tx.epochs_since(from, POLL_LIMIT).await?;
        tx.commit().await?;
        let mut cache = self.cache.lock().map_err(poisoned)?;
        for m in &moved {
            cache.observe(m.subject, m.session_epoch, now_ms);
            cache.advance(m.at_ms);
        }
        Ok(moved.len())
    }
}
