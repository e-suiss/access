use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};

use sha2::{Digest as _, Sha256};

use super::*;
use crate::Hash;
use crate::merkle::Frontier;
use crate::sequencer::{Head, Params, Slot};

struct Rec(u8);

impl Entry for Rec {
    type Sealed = Slot;
    type Error = ();

    fn seal(&self, slot: &Slot) -> Result<(Hash, Slot), ()> {
        let mut h = Sha256::new();
        h.update([self.0]);
        h.update(slot.pos.to_be_bytes());
        Ok((h.finalize().into(), *slot))
    }
}

struct Store {
    answer: AtomicU8,
}

impl LogStore<Slot> for Store {
    type Error = &'static str;

    fn append(
        &self,
        _: &Batch<Slot>,
    ) -> impl Future<Output = Result<(), AppendError<&'static str>>> + Send {
        let answer = match self.answer.swap(0, Ordering::SeqCst) {
            1 => Err(AppendError::Refused("read set")),
            2 => Err(AppendError::Failed("head moved")),
            _ => Ok(()),
        };
        async move { answer }
    }
}

fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn genesis() -> Head {
    let mut frontier = Frontier::default();
    frontier.push([7; 32]).unwrap();
    Head {
        pos: 0,
        leaf: [7; 32],
        recorded_at: 1,
        frontier,
    }
}

fn store(answer: u8) -> Store {
    Store {
        answer: AtomicU8::new(answer),
    }
}

// TI-6, §17.1.1 steps 10–12: a durable append moves the head and the fence together
#[test]
fn a_durable_append_moves_head_and_fence() {
    let mut seq = Sequencer::lead(1, genesis());
    let mut fence = Fence::at(0);
    let pos = run(commit(
        &mut seq,
        &mut fence,
        &store(0),
        5,
        &[Rec(1), Rec(2)],
    ))
    .unwrap();
    assert_eq!((pos, seq.head().pos, fence.durable()), (2, 2, Some(2)));
}

// §17.1.1 step 9: a refused batch keeps the leader and the head
#[test]
fn a_refused_append_keeps_the_leader() {
    let mut seq = Sequencer::lead(1, genesis());
    let mut fence = Fence::at(0);
    let refused = store(1);
    assert_eq!(
        run(commit(&mut seq, &mut fence, &refused, 5, &[Rec(1)])),
        Err(CommitError::Refused("read set"))
    );
    assert!(!seq.stepped_down());
    assert_eq!((seq.head().pos, fence.durable()), (0, Some(0)));
    assert_eq!(
        run(commit(&mut seq, &mut fence, &store(0), 6, &[Rec(1)])),
        Ok(1)
    );
}

// TI-2, TI-9: a failed append steps the writer down and nothing becomes durable
#[test]
fn a_failed_append_steps_down() {
    let mut seq = Sequencer::lead(1, genesis());
    let mut fence = Fence::at(0);
    let failed = store(2);
    assert_eq!(
        run(commit(&mut seq, &mut fence, &failed, 5, &[Rec(1)])),
        Err(CommitError::Failed("head moved"))
    );
    assert!(seq.stepped_down());
    assert_eq!(fence.durable(), Some(0));
    assert!(matches!(
        run(commit(&mut seq, &mut fence, &store(0), 6, &[Rec(1)])),
        Err(CommitError::Plan(PlanError::SteppedDown))
    ));
}

// OP-140 m.5: the batch limit can be lowered and not raised
#[test]
fn batch_parameters_only_narrow() {
    let p = Params::default().with_max_batch(2).unwrap();
    assert!(p.with_max_batch(3).is_err() && p.with_max_batch(0).is_err());
    let mut seq = Sequencer::lead_with(1, genesis(), p);
    let mut fence = Fence::at(0);
    assert!(matches!(
        run(commit(
            &mut seq,
            &mut fence,
            &store(0),
            5,
            &[Rec(1), Rec(2), Rec(3)]
        )),
        Err(CommitError::Plan(PlanError::Size))
    ));
}
