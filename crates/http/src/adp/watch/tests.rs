#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

// §9.7A.2, OP-158 m.3 (u)
#[test]
fn from_is_required_and_canonical_and_wait_is_capped() {
    assert_eq!(query(Some("from=7")).unwrap().0, 7);
    assert_eq!(
        query(Some("from=7")).unwrap().1,
        Duration::from_millis(DEFAULT_WAIT_MS)
    );
    assert_eq!(query(Some("from=0&wait=0")).unwrap().1, Duration::ZERO);
    assert_eq!(query(Some("from=1&wait=999999")).unwrap().1, MAX_WAIT);
    assert_eq!(query(None), Err("from"));
    assert_eq!(query(Some("from=07")), Err("from"));
    assert_eq!(query(Some("from=-1")), Err("from"));
    assert_eq!(query(Some("from=1&wait=x")), Err("wait"));
    assert!(query(Some("from=1&from=2")).is_err());
}
