//! The read replica rule (OP-27, §17.4.6, OPI-2, OP-54-RL2, OP-158 m.3 (n)): every read whose
//! result feeds a security decision goes to the primary; the replica serves only admin search
//! and listing, reports and audit trail viewing, and a user's own profile under LSN
//! read-your-writes. A replica further behind than its threshold is taken out of use. Only the
//! modules xtask `replica-reads` allows hold a [`ReplicaReads`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sqlx::PgPool;

use crate::StoreError;

/// A position in the write-ahead log, in bytes from `0/0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lsn(pub u64);

/// The primary's current WAL position, taken after a write (§17.4.6).
///
/// # Errors
/// [`StoreError`].
pub async fn current_lsn(primary: &PgPool) -> Result<Lsn, StoreError> {
    let at =
        sqlx::query_scalar!(r#"SELECT (pg_current_wal_lsn() - '0/0'::pg_lsn)::bigint AS "at!""#)
            .fetch_one(primary)
            .await?;
    Ok(Lsn(u64::try_from(at).map_err(|_| StoreError::Corrupt)?))
}

/// What a replica has replayed and how far behind it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replay {
    /// Replayed up to here; `None` when the server is not a standby.
    pub at: Option<Lsn>,
    /// Milliseconds since the last replayed commit, when it still has WAL to replay.
    pub behind_ms: Option<u64>,
}

/// The replica's replay position and lag (§17.4.6).
///
/// # Errors
/// [`StoreError`].
pub async fn replay(replica: &PgPool) -> Result<Replay, StoreError> {
    let row = sqlx::query!(
        r#"SELECT (pg_last_wal_replay_lsn() - '0/0'::pg_lsn)::bigint AS at,
                  CASE WHEN pg_last_wal_receive_lsn() IS DISTINCT FROM pg_last_wal_replay_lsn()
                       THEN (extract(epoch FROM clock_timestamp() - pg_last_xact_replay_timestamp()) * 1000)::bigint
                  END AS behind_ms"#
    )
    .fetch_one(replica)
    .await?;
    Ok(Replay {
        at: row.at.and_then(|a| u64::try_from(a).ok()).map(Lsn),
        behind_ms: row.behind_ms.map(|b| u64::try_from(b).unwrap_or(0)),
    })
}

/// The longest a replica may lag before it is taken out of use (§17.4.6, PD).
pub const MAX_LAG: Duration = Duration::from_secs(5);

/// The pools of the non-security reads: the replica while it keeps up, else the primary.
#[derive(Clone)]
pub struct ReplicaReads {
    primary: PgPool,
    replica: Option<PgPool>,
    max_lag: Duration,
    usable: Arc<AtomicBool>,
}

impl ReplicaReads {
    /// No replica: every read goes to the primary.
    #[must_use]
    pub fn primary_only(primary: PgPool) -> Self {
        Self {
            primary,
            replica: None,
            max_lag: MAX_LAG,
            usable: Arc::new(AtomicBool::new(false)),
        }
    }

    /// `replica` beside `primary`, out of use until [`ReplicaReads::probe`] finds it within
    /// `max_lag`.
    #[must_use]
    pub fn new(primary: PgPool, replica: PgPool, max_lag: Duration) -> Self {
        Self {
            primary,
            replica: Some(replica),
            max_lag,
            usable: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether the replica is in use.
    #[must_use]
    pub fn replica_in_use(&self) -> bool {
        self.replica.is_some() && self.usable.load(Ordering::SeqCst)
    }

    /// The pool of an admin search or listing, a report or an audit trail view (OP-27).
    #[must_use]
    pub fn listing(&self) -> &PgPool {
        match &self.replica {
            Some(r) if self.usable.load(Ordering::SeqCst) => r,
            _ => &self.primary,
        }
    }

    /// The pool of a user's own profile read after their write at `written` (§17.4.6): the
    /// replica only once it has replayed that position, else the primary.
    pub async fn own_profile(&self, written: Option<Lsn>) -> &PgPool {
        let Some(replica) = self.replica.as_ref().filter(|_| self.replica_in_use()) else {
            return &self.primary;
        };
        let Some(written) = written else {
            return replica;
        };
        match replay(replica).await {
            Ok(Replay { at: Some(at), .. }) if at >= written => replica,
            _ => &self.primary,
        }
    }

    /// One health round: the replica is in use only while it answers as a standby within the
    /// lag threshold (§17.4.6). Returns whether it is in use.
    pub async fn probe(&self) -> bool {
        let Some(replica) = &self.replica else {
            return false;
        };
        let ok = matches!(
            tokio::time::timeout(crate::connect::PROBE_TIMEOUT, replay(replica)).await,
            Ok(Ok(Replay { at: Some(_), behind_ms })) if behind_ms.is_none_or(|b| u128::from(b) <= self.max_lag.as_millis())
        );
        let was = self.usable.swap(ok, Ordering::SeqCst);
        if was && !ok {
            tracing::warn!(
                event = "replica.reads.lagging",
                outcome = "out_of_use",
                "the read replica is behind its threshold or not a standby; reads go to the primary (OP-27)"
            );
        }
        ok
    }

    /// Runs [`ReplicaReads::probe`] every `every`.
    pub async fn watch(self, every: Duration) {
        loop {
            self.probe().await;
            tokio::time::sleep(every).await;
        }
    }
}
