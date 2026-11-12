//! The leader over an in-memory log whose faults the test controls (OP-8).

#![allow(
    clippy::unused_async_trait_impl,
    clippy::items_after_statements,
    clippy::arithmetic_side_effects,
    reason = "the in-memory port implements an async trait without awaiting; test code"
)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::permit::WritePermit;

use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::record::{Header, Opened, RecordEnvelope, RecordKind};
use access_store::StoreError;
use access_store::authority::{CommitBatch, HeadRow, Lease, LogRecord, NonceRow, Renewal};
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
    commits: usize,
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

    async fn renew(&self, _: Lease) -> Result<Renewal, SequencerError> {
        Ok(Renewal::Extended)
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
        s.commits += 1;
        Ok(())
    }
}

fn item(tag: &str) -> Item {
    let fields = BTreeMap::from([
        (
            "note".to_owned(),
            Opened {
                value: Value::text(tag),
                salt: [1; 32],
            },
        ),
        (
            "outcome".to_owned(),
            Opened {
                value: Value::Map(vec![(Value::text("outcome"), Value::text("deny"))]),
                salt: [3; 32],
            },
        ),
    ]);
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
        beside: Vec::new(),
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
    assert!(
        l.commit(WritePermit::for_tests(), 20, &[item("a")])
            .await
            .is_err()
    );
    assert_eq!(l.head().pos, 0);
    assert!(matches!(
        l.commit(WritePermit::for_tests(), 21, &[item("b")]).await,
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
        async fn renew(&self, l: Lease) -> Result<Renewal, SequencerError> {
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
    old.commit(WritePermit::for_tests(), 20, &[item("a")])
        .await
        .unwrap();
    let mut new = Leader::acquire(Shared(log.clone()), d, key())
        .await
        .unwrap();
    assert!(matches!(
        old.commit(WritePermit::for_tests(), 21, &[item("b")]).await,
        Err(SequencerError::Store(StoreError::HeadMoved))
    ));
    assert!(
        matches!(new.commit(WritePermit::for_tests(), 22, &[item("c")]).await.unwrap(), Outcome::Appended(p) if p == [2])
    );
}

// G34, U30
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
        l.commit(WritePermit::for_tests(), 20, &[g]).await,
        Err(SequencerError::Genesis)
    ));
}

fn with_rw(tag: &str, reads: &[&[u8]], writes: &[&[u8]]) -> Item {
    let mut i = item(tag);
    i.reads = reads.iter().map(|k| (k.to_vec(), 0)).collect();
    i.writes = writes.iter().map(|k| k.to_vec()).collect();
    i
}

// OP-9, T7, PI-23, TI-7, Ek B 5755
#[tokio::test]
async fn op_9_independent_commits_share_one_batch_and_change_nothing_else() {
    use super::group::Grouped;
    let groups = vec![
        vec![with_rw("a", &[b"x"], &[b"x"])],
        vec![
            with_rw("b1", &[b"y"], &[b"y"]),
            with_rw("b2", &[b"y2"], &[]),
        ],
        vec![with_rw("c", &[b"z"], &[b"z"])],
    ];
    let (log, d) = MemLog::with_genesis();
    let mut grouped = Leader::acquire(log, d, key()).await.unwrap();
    let out = grouped
        .commit_group(WritePermit::for_tests(), 20, &groups)
        .await
        .unwrap();
    let positions: Vec<Vec<u64>> = out
        .into_iter()
        .map(|g| match g {
            Grouped::Done(Outcome::Appended(p)) => p,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(positions, vec![vec![1], vec![2, 3], vec![4]]);
    assert_eq!(
        grouped.log.state().commits,
        1,
        "one transaction, one WAL flush"
    );

    let (log, _) = MemLog::with_genesis();
    let mut alone = Leader::acquire(log, d, key()).await.unwrap();
    let all: Vec<Item> = groups.iter().flatten().cloned().collect();
    alone
        .commit(WritePermit::for_tests(), 20, &all)
        .await
        .unwrap();
    let leaves = |l: &Leader<MemLog>| -> Vec<[u8; 32]> {
        l.log.state().records.iter().map(|r| r.leaf_hash).collect()
    };
    assert_eq!(
        leaves(&grouped),
        leaves(&alone),
        "grouping changes no record"
    );
    assert_eq!(grouped.head(), alone.head());
}

// PI-23, TI-7, OP-9
#[tokio::test]
async fn pi_23_a_member_reading_an_earlier_members_write_is_handed_back() {
    use super::group::Grouped;
    let (log, d) = MemLog::with_genesis();
    let mut l = Leader::acquire(log, d, key()).await.unwrap();
    let mut again = item("n2");
    again.nonce = Some(crate::domain::NonceUse {
        nonce: b"same".to_vec(),
        actor: b"a".to_vec(),
        intent_digest: [5; 32],
        outcome: String::from("deny"),
        render_digest: None,
        tier: None,
    });
    let mut first = item("n1");
    first.nonce = again.nonce.clone();
    let out = l
        .commit_group(
            WritePermit::for_tests(),
            20,
            &[
                vec![with_rw("w", &[], &[b"k"])],
                vec![with_rw("r", &[b"k"], &[])],
                vec![first],
                vec![again],
                vec![with_rw("free", &[b"other"], &[])],
            ],
        )
        .await
        .unwrap();
    assert!(matches!(&out[0], Grouped::Done(Outcome::Appended(p)) if p == &[1]));
    assert!(matches!(
        &out[1],
        Grouped::Refused(SequencerError::BatchConflict(_))
    ));
    assert!(matches!(&out[2], Grouped::Done(Outcome::Appended(p)) if p == &[2]));
    assert!(matches!(
        &out[3],
        Grouped::Refused(SequencerError::NonceRepeated)
    ));
    assert!(matches!(&out[4], Grouped::Done(Outcome::Appended(p)) if p == &[3]));
    assert_eq!(l.log.state().commits, 1);
}

// OP-9, TI-6
#[tokio::test]
async fn op_9_a_failed_group_acknowledges_none_of_its_members() {
    let (log, d) = MemLog::with_genesis();
    log.state().fail_next_commit = true;
    let mut l = Leader::acquire(log, d, key()).await.unwrap();
    assert!(
        l.commit_group(
            WritePermit::for_tests(),
            20,
            &[vec![item("a")], vec![item("b")]]
        )
        .await
        .is_err()
    );
    assert_eq!(l.head().pos, 0);
    assert!(matches!(
        l.commit_group(WritePermit::for_tests(), 21, &[vec![item("c")]])
            .await,
        Err(SequencerError::SteppedDown)
    ));
}

// OP-9
#[tokio::test]
async fn op_9_a_group_closes_at_64_or_after_2_ms() {
    use super::group::{GROUP_MAX, GROUP_WAIT, gather};
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    for i in 0..100u32 {
        tx.send(i).await.unwrap();
    }
    assert_eq!(gather(&mut rx).await.len(), GROUP_MAX);
    assert_eq!(gather(&mut rx).await.len(), 36);
    tx.send(7).await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(gather(&mut rx).await, vec![7]);
    assert!(started.elapsed() >= GROUP_WAIT);
    drop(tx);
    assert_eq!(gather(&mut rx).await, Vec::<u32>::new());
}
