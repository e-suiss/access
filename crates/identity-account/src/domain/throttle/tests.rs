use super::*;

const P: ThrottlePolicy = ThrottlePolicy::DEFAULT;

// OP-146, TN-59
#[test]
fn account_wait_doubles_to_thirty_seconds() {
    let mut s = KeyState::default();
    let mut now = 1_000_000;
    let mut waits = Vec::new();
    for _ in 0..8 {
        s = P.account.fail(&s, now);
        waits.push(s.blocked_until_ms - now);
        now = s.blocked_until_ms;
    }
    assert_eq!(
        waits,
        [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]
    );
    assert_eq!(
        P.account.admit(&s, now - 1),
        Gate::Wait { retry_after_ms: 1 }
    );
    let s = P.account.succeed(&s);
    assert_eq!((s.failures, s.blocked_until_ms), (0, 0));
}

// SA-30
#[test]
fn hundred_consecutive_failures_lock() {
    let mut s = KeyState::default();
    for i in 0..HARD_LOCK_AT {
        assert!(!s.locked, "{i}");
        s = P.account.fail(&s, u64::from(i) * 60_000);
    }
    assert!(s.locked);
    assert_eq!(P.account.admit(&s, u64::MAX), Gate::Locked);
    assert!(P.account.succeed(&s).locked);
    let mut t = KeyState::default();
    for i in 0..HARD_LOCK_AT {
        t = P.account_ip.fail(&t, u64::from(i) * 60_000);
    }
    assert!(!t.locked);
}

// §10.2.1, TN-83
#[test]
fn ip_tiers() {
    let mut s = KeyState::default();
    let now = 5 * DAY_MS;
    let mut bans = Vec::new();
    for _ in 0..25 {
        s = P.ip.fail(&s, now);
        bans.push(s.blocked_until_ms.saturating_sub(now));
    }
    assert_eq!(bans[5], 0);
    assert_eq!(bans[6], 60_000);
    assert_eq!(bans[9], 600_000);
    assert_eq!(bans[14], 900_000);
    assert_eq!(bans[19], 3_600_000);
    assert_eq!(bans[24], DAY_MS);
    assert_eq!(P.ip.succeed(&s), s);
    let later = P.ip.fail(&s, now + 2 * DAY_MS);
    assert_eq!(later.failures, 1);
}

// OP-35, TN-82
#[test]
fn rate_applies_before_any_failure() {
    let mut s = KeyState::default();
    let now = 1_000_000;
    for _ in 0..5 {
        match P.account_ip.admit(&s, now) {
            Gate::Open(n) => s = n,
            other => panic!("{other:?}"),
        }
    }
    assert!(matches!(P.account_ip.admit(&s, now), Gate::Wait { .. }));
}
