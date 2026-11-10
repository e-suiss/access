use super::*;

const fn at(pos: u64, idx: u64) -> AccessPosition {
    AccessPosition { pos, idx }
}

// OP-22, OP-156 m.3 (j)
#[test]
fn an_older_or_repeated_event_is_requeried() {
    assert!(should_requery(None, at(1, 0)));
    assert!(!should_requery(Some(at(4, 2)), at(4, 3)));
    assert!(!should_requery(Some(at(4, 2)), at(5, 0)));
    assert!(should_requery(Some(at(4, 2)), at(4, 2)));
    assert!(should_requery(Some(at(4, 2)), at(4, 1)));
    assert!(should_requery(Some(at(4, 2)), at(3, 9)));
}

// OP-22
#[test]
fn the_tracker_keeps_the_newest_and_requeries_the_rest() {
    let mut a = Applied::default();
    assert_eq!(a.observe(at(7, 0)), Next::Requery);
    assert_eq!(a.observe(at(9, 1)), Next::Apply);
    assert_eq!(a.observe(at(8, 0)), Next::Requery);
    assert_eq!(a.observe(at(9, 1)), Next::Requery);
    assert_eq!(a.last(), Some(at(9, 1)));
}
