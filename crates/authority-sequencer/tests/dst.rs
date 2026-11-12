//! SA-T14, R-6, OP-159 m.3 (bb): deterministic simulation of the domain leader. A seeded
//! scheduler drives trusted time, the record salts, the event-id key and an in-memory log with
//! injected faults (lost acknowledgements, crashes, retries, a second leader acquiring the
//! domain) and checks the log after every run. `ACCESS_DST_SEEDS` sets the number of seeds
//! (64 on a PR; the nightly runs 10⁴), `ACCESS_DST_SEED` replays one.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::unused_async_trait_impl,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use access_authority_sequencer::SequencerError;
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::domain::{Draft, Item, Outcome};
use access_authority_sequencer::permit::WritePermit;
use access_authority_sequencer::ports::DomainLog;
use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::record::{Header, Opened, RecordEnvelope, RecordKind, check_link};
use access_store::StoreError;
use access_store::authority::{CommitBatch, HeadRow, Lease, LogRecord, NonceRow, Renewal};
use suiss_crypto::dcbor::Value;

/// A seeded generator (SplitMix64): the only source of choices in a run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn bytes(&mut self) -> [u8; 32] {
        let words = [self.next(), self.next(), self.next(), self.next()];
        std::array::from_fn(|i| words[i / 8].to_le_bytes()[i % 8])
    }
}

/// What the log does with the next commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    /// The batch is not written; the leader steps down.
    Crash,
    /// The batch is written but the answer is lost; the leader steps down.
    LostAck,
    /// The batch is refused as stale; the leader stays and evaluates again.
    Retry,
}

#[derive(Default)]
struct State {
    records: Vec<LogRecord>,
    head: Option<HeadRow>,
    nonces: Vec<NonceRow>,
    fault: Option<Fault>,
}

#[derive(Clone)]
struct SimLog(Arc<Mutex<State>>);

impl SimLog {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }
}

impl DomainLog for SimLog {
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
        let fault = s.fault.take().unwrap_or(Fault::None);
        match fault {
            Fault::Crash => return Err(SequencerError::Store(StoreError::Corrupt)),
            Fault::Retry => return Err(SequencerError::Store(StoreError::Stale)),
            Fault::None | Fault::LostAck => {}
        }
        let head = s.head.as_ref().unwrap();
        if head.pos != batch.after || head.epoch != batch.epoch {
            return Err(SequencerError::Store(StoreError::HeadMoved));
        }
        s.records.extend(batch.records.iter().cloned());
        s.nonces.extend(batch.nonces.iter().cloned());
        s.head = Some(batch.head.clone());
        if fault == Fault::LostAck {
            return Err(SequencerError::Store(StoreError::Corrupt));
        }
        Ok(())
    }
}

fn genesis(rng: &mut Rng) -> (SimLog, Digest) {
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
                salt: rng.bytes(),
            },
        )]),
    };
    let leaf = env.leaf_hash().unwrap();
    let state = State {
        records: vec![LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 10,
            leaf_hash: leaf,
            envelope: env.to_bytes().unwrap(),
        }],
        head: Some(HeadRow {
            pos: 0,
            epoch: 0,
            leaf_hash: leaf,
            recorded_at: 10,
            frontier: vec![leaf],
        }),
        ..State::default()
    };
    (SimLog(Arc::new(Mutex::new(state))), env.domain().unwrap())
}

fn item(tag: &str, rng: &mut Rng) -> Item {
    let fields = BTreeMap::from([
        (
            "note".to_owned(),
            Opened {
                value: Value::text(tag),
                salt: rng.bytes(),
            },
        ),
        (
            "outcome".to_owned(),
            Opened {
                value: Value::Map(vec![(Value::text("outcome"), Value::text("deny"))]),
                salt: rng.bytes(),
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

/// The note of the record at `pos` in `records`.
fn note_at(records: &[LogRecord], pos: u64) -> Option<String> {
    let r = records.iter().find(|r| r.pos == pos)?;
    let env = RecordEnvelope::from_bytes(&r.envelope).ok()?;
    match &env.fields.get("note")?.value {
        Value::Text(t) => Some(t.clone()),
        _ => None,
    }
}

/// One simulated run: its trace and the first broken invariant, if any.
struct Run {
    trace: Vec<String>,
    broken: Option<String>,
}

const STEPS: u64 = 48;

#[expect(
    clippy::too_many_lines,
    reason = "the scheduler's actions and the invariants, in one place"
)]
fn simulate(seed: u64) -> Run {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut rng = Rng(seed);
    let (log, domain) = genesis(&mut rng);
    let key_bytes = rng.bytes();
    let key = || EventKey::new(Secret::new(key_bytes));
    let mut leaders: Vec<Option<Leader<SimLog>>> = vec![
        Some(
            rt.block_on(Leader::acquire(log.clone(), domain, key()))
                .unwrap(),
        ),
        None,
    ];
    let mut now: u64 = 1_000;
    let mut trace = Vec::new();
    let mut acked: BTreeMap<u64, String> = BTreeMap::new();
    let mut next_tag = 0_u64;
    let mut broken = None;
    for step in 0..STEPS {
        now += 1 + rng.below(5);
        match rng.below(10) {
            0 | 1 => {
                let slot = usize::try_from(rng.below(2)).unwrap();
                match rt.block_on(Leader::acquire(log.clone(), domain, key())) {
                    Ok(l) => {
                        trace.push(format!("{step}: acquire {slot} epoch {}", l.epoch()));
                        leaders[slot] = Some(l);
                    }
                    Err(e) => trace.push(format!("{step}: acquire {slot} refused {e}")),
                }
            }
            _ => {
                let slot = usize::try_from(rng.below(2)).unwrap();
                let Some(leader) = leaders[slot].as_mut() else {
                    trace.push(format!("{step}: idle {slot}"));
                    continue;
                };
                let fault = match rng.below(12) {
                    0 => Fault::Crash,
                    1 => Fault::LostAck,
                    2 => Fault::Retry,
                    _ => Fault::None,
                };
                log.state().fault = Some(fault);
                let n = 1 + rng.below(3);
                let tags: Vec<String> = (0..n)
                    .map(|_| {
                        next_tag += 1;
                        format!("t{next_tag}")
                    })
                    .collect();
                let items: Vec<Item> = tags.iter().map(|t| item(t, &mut rng)).collect();
                let out = rt.block_on(leader.commit(WritePermit::for_tests(), now, &items));
                log.state().fault = None;
                match out {
                    Ok(Outcome::Appended(positions)) => {
                        trace.push(format!("{step}: commit {slot} {fault:?} -> {positions:?}"));
                        if positions.len() != tags.len() {
                            broken.get_or_insert(format!(
                                "seed {seed} step {step}: {} items acknowledged at {positions:?}",
                                tags.len()
                            ));
                        }
                        for (p, t) in positions.iter().zip(&tags) {
                            if let Some(before) = acked.insert(*p, t.clone()) {
                                broken.get_or_insert(format!(
                                    "seed {seed} step {step}: position {p} acknowledged twice ({before}, {t})"
                                ));
                            }
                        }
                    }
                    Ok(Outcome::Replayed(p)) => {
                        trace.push(format!("{step}: commit {slot} replayed {p}"));
                        broken.get_or_insert(format!(
                            "seed {seed} step {step}: a commit without a nonce replayed {p}"
                        ));
                    }
                    Err(e) => {
                        let kind = if e.is_retry() { "retry" } else { "error" };
                        trace.push(format!("{step}: commit {slot} {fault:?} -> {kind} {e}"));
                    }
                }
            }
        }
        let s = log.state();
        for (p, t) in &acked {
            if note_at(&s.records, *p).as_deref() != Some(t.as_str()) {
                broken.get_or_insert(format!(
                    "seed {seed} step {step}: acknowledged {t} is not the record at {p}"
                ));
            }
        }
    }
    let s = log.state();
    let mut previous = None;
    for (i, r) in s.records.iter().enumerate() {
        let core = RecordEnvelope::from_bytes(&r.envelope)
            .ok()
            .and_then(|e| e.leaf_core().ok());
        let Some(core) = core else {
            broken.get_or_insert(format!("seed {seed}: record {i} does not decode"));
            break;
        };
        if u64::try_from(i).ok() != Some(r.pos) || core.header.pos != r.pos {
            broken.get_or_insert(format!("seed {seed}: position {} at index {i}", r.pos));
        }
        if core.leaf_hash().ok() != Some(r.leaf_hash) {
            broken.get_or_insert(format!("seed {seed}: leaf hash of {} differs", r.pos));
        }
        if let Some(prev) = &previous
            && check_link(prev, &core, &domain).is_err()
        {
            broken.get_or_insert(format!("seed {seed}: record {} does not chain", r.pos));
        }
        previous = Some(core);
    }
    if let Some(head) = &s.head
        && s.records.last().map(|r| r.pos) != Some(head.pos)
    {
        broken.get_or_insert(format!("seed {seed}: the head is not the last record"));
    }
    Run { trace, broken }
}

fn seeds() -> Vec<u64> {
    if let Some(one) = std::env::var("ACCESS_DST_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        return vec![one];
    }
    let n = std::env::var("ACCESS_DST_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64_u64);
    (1..=n).collect()
}

// SA-T14, R-6
#[test]
fn sa_t14_the_same_seed_replays_the_same_trace() {
    for seed in [1_u64, 7, 4242] {
        let a = simulate(seed);
        let b = simulate(seed);
        assert_eq!(a.trace, b.trace, "seed {seed}");
        assert_eq!(a.trace.len(), usize::try_from(STEPS).unwrap());
    }
    assert_ne!(simulate(1).trace, simulate(2).trace);
}

// SA-T14, TI-6, TI-2
#[test]
fn sa_t14_acknowledged_records_are_in_the_log_and_no_position_is_written_twice() {
    let mut seen = std::collections::BTreeSet::new();
    for seed in seeds() {
        let run = simulate(seed);
        assert_eq!(run.broken, None, "replay with ACCESS_DST_SEED={seed}");
        for line in &run.trace {
            for mark in [
                "LostAck -> error",
                "Crash -> error",
                "Retry -> retry",
                "leader stepped down",
                "acquire 1",
                "None -> [",
            ] {
                if line.contains(mark) {
                    seen.insert(mark);
                }
            }
        }
    }
    if std::env::var("ACCESS_DST_SEED").is_err() {
        assert_eq!(seen.len(), 6, "the schedule reached only {seen:?}");
    }
}

// SA-T14, TI-2
#[test]
fn sa_t14_a_fenced_leader_cannot_write_after_a_new_leader_acquired() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut rng = Rng(99);
    let (log, domain) = genesis(&mut rng);
    let k = rng.bytes();
    let mut old = rt
        .block_on(Leader::acquire(
            log.clone(),
            domain,
            EventKey::new(Secret::new(k)),
        ))
        .unwrap();
    let mut new = rt
        .block_on(Leader::acquire(
            log.clone(),
            domain,
            EventKey::new(Secret::new(k)),
        ))
        .unwrap();
    let first = item("old", &mut rng);
    let err = rt
        .block_on(old.commit(WritePermit::for_tests(), 2_000, &[first]))
        .unwrap_err();
    assert!(matches!(err, SequencerError::Store(StoreError::HeadMoved)));
    let again = item("old-again", &mut rng);
    assert!(matches!(
        rt.block_on(old.commit(WritePermit::for_tests(), 2_001, &[again])),
        Err(SequencerError::SteppedDown)
    ));
    let fresh = item("new", &mut rng);
    assert!(matches!(
        rt.block_on(new.commit(WritePermit::for_tests(), 2_002, &[fresh])).unwrap(),
        Outcome::Appended(p) if p == [1]
    ));
    assert_eq!(note_at(&log.state().records, 1).as_deref(), Some("new"));
}
