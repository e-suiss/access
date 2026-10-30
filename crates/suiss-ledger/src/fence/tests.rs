use super::*;

const fn c(pos: u64, idx: u32) -> Cursor {
    Cursor { pos, idx }
}

// TI-6, Work OP-3: an event leaves only once its record is durable
#[test]
fn events_wait_for_durability() {
    let mut f = Fence::default();
    let pending = [c(1, 0), c(1, 1), c(2, 0), c(3, 0)];
    assert_eq!(f.releasable(None, &pending), &[] as &[Cursor]);
    f.advance(2).unwrap();
    assert_eq!(f.releasable(None, &pending), &pending[..3]);
    assert_eq!(f.releasable(Some(c(1, 0)), &pending), &pending[1..3]);
    assert_eq!(f.releasable(Some(c(2, 0)), &pending), &[] as &[Cursor]);
    f.advance(3).unwrap();
    assert_eq!(f.releasable(Some(c(2, 0)), &pending), &pending[3..]);
}

// TI-6: the durable position never goes back
#[test]
fn the_fence_only_moves_forward() {
    let mut f = Fence::at(5);
    assert_eq!(f.advance(4), Err(FenceError));
    assert_eq!(f.durable(), Some(5));
    f.advance(5).unwrap();
    assert!(f.allows(5) && !f.allows(6));
}
