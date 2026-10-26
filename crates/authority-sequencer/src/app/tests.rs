//! The leader over an in-memory log whose faults the test controls (OP-8).

#![allow(
    clippy::unused_async_trait_impl,
    clippy::items_after_statements,
    clippy::arithmetic_side_effects,
    reason = "the in-memory port implements an async trait without awaiting; test code"
)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::record::{Header, Opened, RecordEnvelope, RecordKind};
use access_store::StoreError;
use access_store::authority::{CommitBatch, HeadRow, Lease, LogRecord, NonceRow};
use suiss_crypto::dcbor::Value;

use super::Leader;
use crate::SequencerError;
use crate::domain::{Draft, Item, Outcome};
use crate::ports::DomainLog;

#[derive(Default)]
struct State {
    records: Vec<LogRecord>,
    head: Option<HeadRow>,
    nonces: Vec<NonceRow>,
    fail_next_commit: bool,
}

struct MemLog(Mutex<State>);

impl MemLog {
    fn with_genesis() -> (Self, Digest) {
        let env = RecordEnvelope {
            header: Header {
                domain: None,
                pos: 0,
                kind: RecordKind::Genesis,
                recorded_at: 10,
                prev: None,
            },
            fields: BTreeMap::from([(
                "roots".to_owned(),
                Opened {
                    value: Value::text("r"),
                    salt: [4; 32],
                },
            )]),
        };
        let leaf = env.leaf_hash().unwrap();
        let rec = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 10,
            leaf_hash: leaf,
            envelope: env.to_bytes().unwrap(),
        };
        let head = HeadRow {
            pos: 0,
            epoch: 0,
            leaf_hash: leaf,
            recorded_at: 10,
            frontier: vec![leaf],
        };
        let state = State {
            records: vec![rec],
            head: Some(head),
            ..State::default()
        };
        (Self(Mutex::new(state)), env.domain().unwrap())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }
}

impl DomainLog for MemLog {
    async fn acquire(&self) -> Result<(Lease, HeadRow), SequencerError> {
        let mut s = self.state();
        let head = s.head.as_mut().unwrap();
        head.epoch += 1;
        Ok((Lease { epoch: head.epoch }, head.clone()))
    }

    async fn renew(&self, _: Lease) -> Result<(), SequencerError> {
        Ok(())
    }

    async fn release(&self, _: Lease) -> Result<(), SequencerError> {
        Ok(())
    }

    async fn record(&self, pos: u64) -> Result<Option<LogRecord>, SequencerError> {
        Ok(self.state().records.iter().find(|r| r.pos == pos).cloned())
    }

    async fn nonce(&self, nonce: &[u8]) -> Result<Option<NonceRow>, SequencerError> {
        Ok(self
            .state()
            .nonces
            .iter()
            .find(|n| n.nonce == nonce)
            .cloned())
    }

    async fn commit(&self, batch: &CommitBatch) -> Result<(), SequencerError> {
        let mut s = self.state();
        if std::mem::take(&mut s.fail_next_commit) {
            return Err(SequencerError::Store(StoreError::Corrupt));
        }
        let head = s.head.as_ref().unwrap();
        if head.pos != batch.after || head.epoch != batch.epoch {
            return Err(SequencerError::Store(StoreError::HeadMoved));
        }
        s.records.extend(batch.records.iter().cloned());
        s.nonces.extend(batch.nonces.iter().cloned());
        s.head = Some(batch.head.clone());
        Ok(())
    }
}

fn item(tag: &str) -> Item {
    let fields = BTreeMap::from([(
        "note".to_owned(),
        Opened {
            value: Value::text(tag),
            salt: [1; 32],
        },
    )]);
    Item {
        draft: Draft {
            kind: RecordKind::Decision,
            fields,
        },
        nonce: None,
        events: Vec::new(),
        proofs: Vec::new(),
        reads: Vec::new(),
        writes: Vec::new(),
        draws: Vec::new(),
        single_use: Vec::new(),
    }
}

fn key() -> EventKey {
    EventKey::new(Secret::new([2; 32]))
}

#[tokio::test]
async fn a_failed_commit_steps_down_without_moving_the_head() {
    let (log, d) = MemLog::with_genesis();
    log.state().fail_next_commit = true;
    let mut l = Leader::acquire(log, d, key()).await.unwrap();
    assert!(l.commit(20, &[item("a")]).await.is_err());
    assert_eq!(l.head().pos, 0);
    assert!(matches!(
        l.commit(21, &[item("b")]).await,
        Err(SequencerError::SteppedDown)
    ));
}

#[tokio::test]
async fn a_new_epoch_fences_the_previous_leader() {
    let (log, d) = MemLog::with_genesis();
    let log = std::sync::Arc::new(log);
    struct Shared(std::sync::Arc<MemLog>);
    impl DomainLog for Shared {
        async fn acquire(&self) -> Result<(Lease, HeadRow), SequencerError> {
            self.0.acquire().await
        }
        async fn renew(&self, l: Lease) -> Result<(), SequencerError> {
            self.0.renew(l).await
        }
        async fn release(&self, l: Lease) -> Result<(), SequencerError> {
            self.0.release(l).await
        }
        async fn record(&self, p: u64) -> Result<Option<LogRecord>, SequencerError> {
            self.0.record(p).await
        }
        async fn nonce(&self, n: &[u8]) -> Result<Option<NonceRow>, SequencerError> {
            self.0.nonce(n).await
        }
        async fn commit(&self, b: &CommitBatch) -> Result<(), SequencerError> {
            self.0.commit(b).await
        }
    }
    let mut old = Leader::acquire(Shared(log.clone()), d, key())
        .await
        .unwrap();
    old.commit(20, &[item("a")]).await.unwrap();
    let mut new = Leader::acquire(Shared(log.clone()), d, key())
        .await
        .unwrap();
    assert!(matches!(
        old.commit(21, &[item("b")]).await,
        Err(SequencerError::Store(StoreError::HeadMoved))
    ));
    assert!(
        matches!(new.commit(22, &[item("c")]).await.unwrap(), Outcome::Appended(p) if p == [2])
    );
}

#[tokio::test]
async fn a_head_that_disagrees_with_the_log_is_refused() {
    let (log, d) = MemLog::with_genesis();
    log.state().head.as_mut().unwrap().leaf_hash = [9; 32];
    assert!(matches!(
        Leader::acquire(log, d, key()).await,
        Err(SequencerError::Diverged)
    ));
    let (log, _) = MemLog::with_genesis();
    assert!(matches!(
        Leader::acquire(log, Digest([3; 32]), key()).await,
        Err(SequencerError::Diverged)
    ));
}

#[tokio::test]
async fn genesis_cannot_be_appended() {
    let (log, d) = MemLog::with_genesis();
    let mut l = Leader::acquire(log, d, key()).await.unwrap();
    let mut g = item("g");
    g.draft.kind = RecordKind::Genesis;
    assert!(matches!(
        l.commit(20, &[g]).await,
        Err(SequencerError::Genesis)
    ));
}
