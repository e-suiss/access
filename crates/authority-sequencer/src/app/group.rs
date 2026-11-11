//! Group commit (OP-9, §17.1.2, T7, PI-23, TI-7, OP-158 m.3 (n)): independent commits of one
//! domain go into one batch, one transaction and one WAL flush. Grouping never changes
//! semantics: each commit passes its own checks, a commit that reads what an earlier one of the
//! group writes is handed back to be evaluated again, and a commit is acknowledged only once the
//! whole group is durable.

use std::time::Duration;

use access_kernel::model::TrustedTime;
use access_kernel::record::RecordKind;

use super::{Leader, observe};
use crate::SequencerError;
use crate::domain::{Bound, Item, Outcome, check_effects, independent, nonces, replay, rows};
use crate::ports::DomainLog;
use access_telemetry::metrics::Stopwatch;

/// The most items one group carries (OP-9, PD; tuned by measurement).
pub const GROUP_MAX: usize = 64;

/// The longest a commit waits for others to join its group (OP-9, PD; tuned by measurement).
pub const GROUP_WAIT: Duration = Duration::from_millis(2);

/// What became of one commit of a group.
#[derive(Debug)]
pub enum Grouped {
    /// Committed with the group, or a replay of a committed nonce.
    Done(Outcome),
    /// Not committed: it reads what an earlier commit of the group writes, or its own checks
    /// refused it; the caller evaluates it again or answers the error.
    Refused(SequencerError),
}

impl<L: DomainLog> Leader<L> {
    /// Commits `groups` together at trusted time `now` (OP-9): each group is one caller's
    /// commit, checked on its own as [`Leader::commit`] checks it; the ones that pass are
    /// sealed into one batch in the given order and written in one transaction. A failure of
    /// that transaction fails every member and, as in [`Leader::commit`], steps the leader
    /// down unless it is a retry.
    ///
    /// # Errors
    /// [`SequencerError::SteppedDown`] before anything is tried; the batch's own failure.
    pub async fn commit_group(
        &mut self,
        now: TrustedTime,
        groups: &[Vec<Item>],
    ) -> Result<Vec<Grouped>, SequencerError> {
        if self.seq.stepped_down() {
            return Err(SequencerError::SteppedDown);
        }
        let mut out: Vec<Option<Grouped>> = Vec::with_capacity(groups.len());
        let mut kept: Vec<usize> = Vec::new();
        let mut used = std::collections::BTreeSet::new();
        for (g, items) in groups.iter().enumerate() {
            match self.precheck(items).await {
                Ok(Some(outcome)) => out.push(Some(Grouped::Done(outcome))),
                Ok(None) => {
                    let mine: Vec<Vec<u8>> = nonces(items)?
                        .into_iter()
                        .map(|n| n.nonce.clone())
                        .collect();
                    if mine.iter().any(|n| used.contains(n)) {
                        out.push(Some(Grouped::Refused(SequencerError::NonceRepeated)));
                        continue;
                    }
                    used.extend(mine);
                    out.push(None);
                    kept.push(g);
                }
                Err(e) => out.push(Some(Grouped::Refused(e))),
            }
        }
        // PI-23, TI-7
        loop {
            let all: Vec<Item> = kept
                .iter()
                .filter_map(|g| groups.get(*g))
                .flat_map(|items| items.iter().cloned())
                .collect();
            match independent(&all) {
                Ok(()) => break,
                Err(SequencerError::BatchConflict(i)) => {
                    let mut seen = 0usize;
                    let Some(at) = kept.iter().position(|g| {
                        seen = seen.saturating_add(groups.get(*g).map_or(0, Vec::len));
                        seen > i
                    }) else {
                        return Err(SequencerError::BatchConflict(i));
                    };
                    let g = kept.remove(at);
                    if let Some(slot) = out.get_mut(g) {
                        *slot = Some(Grouped::Refused(SequencerError::BatchConflict(0)));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        if kept.is_empty() {
            return Ok(out
                .into_iter()
                .map(|o| o.unwrap_or(Grouped::Refused(SequencerError::BatchConflict(0))))
                .collect());
        }
        let items: Vec<Item> = kept
            .iter()
            .filter_map(|g| groups.get(*g))
            .flat_map(|items| items.iter().cloned())
            .collect();
        let entries: Vec<Bound<'_>> = items
            .iter()
            .map(|i| Bound {
                domain: self.domain,
                draft: &i.draft,
            })
            .collect();
        let batch = self.seq.plan(now, &entries)?;
        let mut stored = match rows(&self.domain.0, &self.key, &items, &batch) {
            Ok(stored) => stored,
            Err(e) => {
                self.seq.failed();
                return Err(e);
            }
        };
        let trace_parent = access_telemetry::trace::current_header();
        for row in &mut stored.outbox {
            row.trace_parent.clone_from(&trace_parent);
        }
        let watch = Stopwatch::start();
        let committed = self.log.commit(&stored).await;
        observe(&committed, watch, items.len());
        match committed {
            Ok(()) => {
                self.seq.committed(batch)?;
                self.ring(&stored);
            }
            Err(e) if e.is_retry() => {
                self.seq.abandoned(&batch)?;
                return Err(e);
            }
            Err(e) => {
                self.seq.failed();
                return Err(e);
            }
        }
        let mut positions = stored.records.iter().map(|r| r.pos);
        for g in kept {
            let n = groups.get(g).map_or(0, Vec::len);
            let own: Vec<u64> = positions.by_ref().take(n).collect();
            if let Some(slot) = out.get_mut(g) {
                *slot = Some(Grouped::Done(Outcome::Appended(own)));
            }
        }
        Ok(out
            .into_iter()
            .map(|o| o.unwrap_or(Grouped::Refused(SequencerError::BatchConflict(0))))
            .collect())
    }

    /// One member's own checks, as [`Leader::commit`] runs them: `Some` for a replay of a
    /// committed nonce.
    async fn precheck(&self, items: &[Item]) -> Result<Option<Outcome>, SequencerError> {
        if items.iter().any(|i| i.draft.kind == RecordKind::Genesis) {
            return Err(SequencerError::Genesis);
        }
        independent(items)?;
        check_effects(items)?;
        for n in nonces(items)? {
            if let Some(stored) = self.log.nonce(&n.nonce).await?
                && let Some(pos) = replay(n, &stored, items.len() == 1)?
            {
                return Ok(Some(Outcome::Replayed(pos)));
            }
        }
        Ok(None)
    }
}

/// Collects up to [`GROUP_MAX`] waiting commits, waiting at most [`GROUP_WAIT`] after the first
/// (OP-9): the group a leader commits in one transaction.
pub async fn gather<T>(rx: &mut tokio::sync::mpsc::Receiver<T>) -> Vec<T> {
    let Some(first) = rx.recv().await else {
        return Vec::new();
    };
    let mut group = vec![first];
    let deadline = tokio::time::Instant::now()
        .checked_add(GROUP_WAIT)
        .unwrap_or_else(tokio::time::Instant::now);
    while group.len() < GROUP_MAX {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(next)) => group.push(next),
            Ok(None) | Err(_) => break,
        }
    }
    group
}
