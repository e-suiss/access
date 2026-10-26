#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use super::{Batch, Entry, Head, MAX_BATCH, PlanError, Sequencer, Slot};
use crate::Hash;
use crate::merkle::Frontier;

struct Rec(u8);

impl Entry for Rec {
    type Sealed = Slot;
    type Error = ();

    fn seal(&self, slot: &Slot) -> Result<(Hash, Slot), ()> {
        if self.0 == 0xff {
            return Err(());
        }
        let mut h = Sha256::new();
        h.update([self.0]);
        h.update(slot.pos.to_be_bytes());
        h.update(slot.prev);
        h.update(slot.recorded_at.to_be_bytes());
        Ok((h.finalize().into(), *slot))
    }
}

fn genesis() -> Head {
    let leaf = [7; 32];
    let mut frontier = Frontier::default();
    frontier.push(leaf).unwrap();
    Head {
        pos: 0,
        leaf,
        recorded_at: 100,
        frontier,
    }
}

#[test]
fn batch_chains_positions_and_never_lowers_time() {
    let mut s = Sequencer::lead(1, genesis());
    let b = s.plan(50, &[Rec(1), Rec(2)]).unwrap();
    assert_eq!(b.after, 0);
    assert_eq!(
        b.records[0].slot,
        Slot {
            pos: 1,
            prev: [7; 32],
            recorded_at: 100
        }
    );
    assert_eq!(b.records[1].slot.prev, b.records[0].leaf);
    assert_eq!(b.head.pos, 2);
    assert_eq!(b.head.frontier.size(), 3);
    s.committed(b).unwrap();
    let b = s.plan(200, &[Rec(3)]).unwrap();
    assert_eq!(b.records[0].slot.recorded_at, 200);
    assert_eq!(b.after, 2);
}

#[test]
fn head_moves_only_on_commit() {
    let mut s = Sequencer::lead(1, genesis());
    let _b = s.plan(100, &[Rec(1)]).unwrap();
    assert_eq!(s.head().pos, 0);
    assert_eq!(s.plan(100, &[Rec(2)]).unwrap_err(), PlanError::InFlight);
}

#[test]
fn failed_commit_steps_down() {
    let mut s = Sequencer::lead(1, genesis());
    let _b = s.plan(100, &[Rec(1)]).unwrap();
    s.failed();
    assert!(s.stepped_down());
    assert_eq!(s.head().pos, 0);
    assert_eq!(s.plan(100, &[Rec(2)]).unwrap_err(), PlanError::SteppedDown);
}

#[test]
fn foreign_outcome_steps_down() {
    let mut s = Sequencer::lead(2, genesis());
    let b = s.plan(100, &[Rec(1)]).unwrap();
    let forged = Batch { epoch: 1, ..b };
    assert!(s.committed(forged).is_err());
    assert!(s.stepped_down());
}

#[test]
fn size_and_seal_errors_leave_no_batch_in_flight() {
    let mut s = Sequencer::lead(1, genesis());
    assert_eq!(s.plan::<Rec>(100, &[]).unwrap_err(), PlanError::Size);
    let many: Vec<Rec> = (0..=MAX_BATCH).map(|_| Rec(1)).collect();
    assert_eq!(s.plan(100, &many).unwrap_err(), PlanError::Size);
    assert_eq!(
        s.plan(100, &[Rec(1), Rec(0xff)]).unwrap_err(),
        PlanError::Seal(())
    );
    assert!(s.plan(100, &[Rec(1)]).is_ok());
}

#[test]
fn position_overflow_is_an_error() {
    let leaf = [1; 32];
    let frontier = Frontier::from_parts(u64::MAX, (0..64).map(|_| leaf).collect()).unwrap();
    let mut s = Sequencer::lead(
        1,
        Head {
            pos: u64::MAX,
            leaf,
            recorded_at: 0,
            frontier,
        },
    );
    assert_eq!(s.plan(0, &[Rec(1)]).unwrap_err(), PlanError::Overflow);
}

// §17.1.1 step 9: a refused batch leaves the leader in place
#[test]
fn an_abandoned_batch_keeps_the_leader() {
    let mut s = Sequencer::lead(1, genesis());
    let b = s.plan(100, &[Rec(1)]).unwrap();
    s.abandoned(&b).unwrap();
    assert!(!s.stepped_down());
    let again = s.plan(100, &[Rec(2)]).unwrap();
    assert_eq!(again.after, 0);
    assert!(
        s.abandoned(&b).is_err(),
        "a stale batch steps the sequencer down"
    );
    assert!(s.stepped_down());
}

#[derive(Clone, Debug)]
enum Op {
    Plan(u8),
    Commit,
    Fail,
    Abandon,
    Stale,
}

fn op() -> impl proptest::strategy::Strategy<Value = Op> {
    use proptest::prelude::*;
    prop_oneof![
        4 => (1_u8..4).prop_map(Op::Plan),
        3 => Just(Op::Commit),
        1 => Just(Op::Fail),
        1 => Just(Op::Abandon),
        1 => Just(Op::Stale),
    ]
}

proptest::proptest! {
    // OP-8, TI-2: against a reference model, under any order of outcomes, the head moves only
    // on the commit of the batch in flight, positions are gapless and never reused, and a
    // sequencer that stepped down plans nothing again
    #[test]
    fn the_engine_follows_its_model(ops in proptest::collection::vec(op(), 1..60)) {
        let mut s = Sequencer::lead(1, genesis());
        let (mut head, mut down) = (0_u64, false);
        let mut in_flight: Option<Batch<Slot>> = None;
        let mut stale: Option<Batch<Slot>> = None;
        let mut seen = alloc::collections::BTreeSet::new();
        for op in ops {
            match op {
                Op::Plan(n) => {
                    let items: Vec<Rec> = (0..n).map(Rec).collect();
                    let r = s.plan(500, &items);
                    match (down, in_flight.is_some()) {
                        (true, _) => proptest::prop_assert_eq!(r.unwrap_err(), PlanError::SteppedDown),
                        (false, true) => proptest::prop_assert_eq!(r.unwrap_err(), PlanError::InFlight),
                        (false, false) => {
                            let b = r.unwrap();
                            proptest::prop_assert_eq!(b.after, head);
                            for (i, rec) in b.records.iter().enumerate() {
                                proptest::prop_assert_eq!(rec.slot.pos, head + 1 + i as u64);
                            }
                            stale = in_flight.replace(b);
                        }
                    }
                }
                Op::Commit => {
                    if let Some(b) = in_flight.take() {
                        let end = b.head.pos;
                        proptest::prop_assert!(s.committed(b).is_ok());
                        for p in head + 1..=end {
                            proptest::prop_assert!(seen.insert(p), "position {} reused", p);
                        }
                        head = end;
                    }
                }
                Op::Fail => {
                    s.failed();
                    down = true;
                    in_flight = None;
                }
                Op::Abandon => {
                    if let Some(b) = in_flight.take() {
                        proptest::prop_assert!(s.abandoned(&b).is_ok());
                        stale = Some(b);
                    }
                }
                Op::Stale => {
                    if let Some(b) = stale.take() {
                        // an outcome for a batch that is not in flight steps the sequencer down
                        proptest::prop_assert!(s.committed(b).is_err());
                        down = true;
                        in_flight = None;
                    }
                }
            }
            proptest::prop_assert_eq!(s.head().pos, head);
            proptest::prop_assert_eq!(s.stepped_down(), down);
            proptest::prop_assert_eq!(s.head().frontier.size(), head + 1);
        }
    }
}
