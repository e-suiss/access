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
