//! The watch stream (§9.7A.2, §9.7A.4, OP-158 m.3 (u)): the records after a position by long
//! polling, each with its trusted time and the kinds of state it changed, and the largest tree
//! size a witness has cosigned (`witnessed_through`). Advisory: a reader drops what a change
//! touched; nothing here is a source of ALLOW. Record contents, ids and bodies are not shown.

use std::collections::BTreeSet;
use std::time::Duration;

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::fold;
use access_kernel::record::RecordEnvelope;
use access_store::Pool;
use access_store::scope::DomainId;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;

/// Most records one answer carries; `next` continues after the last.
pub const MAX_CHANGES: u64 = 100;
/// Longest a request waits for a record after `from`.
pub const MAX_WAIT: Duration = Duration::from_secs(25);
/// How often the head is read again while waiting.
pub const POLL: Duration = Duration::from_millis(50);

/// One record after `from`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// Its position.
    pub position: u64,
    /// Its trusted time, milliseconds.
    pub recorded_at: u64,
    /// The kinds of state key it changed (`grant`, `claim`, `member`, …).
    pub kinds: BTreeSet<String>,
}

/// One watch answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Watched {
    /// The records after `from`, at most [`MAX_CHANGES`], oldest first; empty when none came
    /// in time.
    pub changes: Vec<Change>,
    /// The position to ask from next.
    pub next: u64,
    /// The domain's head when answered.
    pub head: u64,
    /// The largest tree size an independent witness has cosigned; 0 before the first (§16.6,
    /// SEC23).
    pub witnessed_through: u64,
}

/// The kinds of state key `record` changes.
fn kinds(record: &RecordEnvelope) -> BTreeSet<String> {
    fold::effects(record)
        .map(|effects| {
            effects
                .into_iter()
                .filter_map(|(key, _)| match dcbor::decode(&key, Limits::CEILING) {
                    Ok(Value::Array(k)) => match k.into_iter().next() {
                        Some(Value::Text(kind)) => Some(kind),
                        _ => None,
                    },
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The records of `domain` after `from`, waiting up to `wait` (at most [`MAX_WAIT`]) for the
/// first one, read over `app` at trusted time `now`.
///
/// # Errors
/// `as-of-expired` when the first record after `from` is older than the `as_of` window;
/// `consistency` (unavailable) for a `from` past the head; [`CoreError::Store`].
pub async fn watch(
    app: &Pool,
    domain: Digest,
    from: u64,
    wait: Duration,
    now: u64,
) -> Result<Watched, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let start = tokio::time::Instant::now();
    let deadline = start.checked_add(wait.min(MAX_WAIT)).unwrap_or(start);
    let mut head = access_store::authority::read_head(app, &id).await?.pos;
    if from > head {
        return Err(CoreError::Unavailable("consistency"));
    }
    while head == from && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(POLL).await;
        head = access_store::authority::read_head(app, &id).await?.pos;
    }
    let to = head.min(from.saturating_add(MAX_CHANGES));
    let mut changes = Vec::new();
    if to > from {
        for r in access_store::authority::read_log(app, &id, from.saturating_add(1), to).await? {
            // §9.7A.2 k.3
            if changes.is_empty()
                && now.saturating_sub(r.recorded_at) > crate::app::cache::AS_OF_WINDOW_MS
            {
                return Err(CoreError::Refused("as-of-expired"));
            }
            let record = RecordEnvelope::from_bytes(&r.envelope)
                .map_err(|_| CoreError::Store(access_store::StoreError::Corrupt))?;
            changes.push(Change {
                position: r.pos,
                recorded_at: r.recorded_at,
                kinds: kinds(&record),
            });
        }
    }
    let witnessed_through = access_store::witness::witnessed_through(app, &id).await?;
    Ok(Watched {
        next: changes.last().map_or(from, |c| c.position),
        changes,
        head,
        witnessed_through,
    })
}
