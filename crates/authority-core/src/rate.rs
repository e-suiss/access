//! ADP rate limits (§13.7.4, OP-35 layer A, OP-141 m.23): counted in the leader's memory per
//! actor Instance, or per PEP for an anonymous request, against trusted time.

use std::collections::HashMap;

use access_kernel::model::Id;

/// Commit tokens per second and the burst (§13.7.4, PD).
pub const COMMIT: (u64, u64) = (20, 100);
/// Check per minute and per day.
pub const CHECK: (u64, u64) = (60, 2_000);
/// Explain per minute and per day.
pub const EXPLAIN: (u64, u64) = (30, 500);
/// Search per minute; no daily limit.
pub const SEARCH: u64 = 10;

/// Entries kept before idle ones are dropped.
const KEEP: usize = 100_000;

const MINUTE: u64 = 60_000;
const DAY: u64 = 86_400_000;

/// What is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// `commit` and `continue`.
    Commit,
    /// `check`.
    Check,
    /// `explain`.
    Explain,
    /// `search`.
    Search,
}

/// Who is counted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Who {
    /// An actor Instance.
    Instance(Id),
    /// The PEP of an anonymous request.
    Pep(String),
}

#[derive(Clone, Copy, Debug, Default)]
struct Window {
    minute: (u64, u64),
    day: (u64, u64),
    /// Commit bucket: thousandths of a token, and when it was last filled.
    bucket: (u64, u64),
    seen: u64,
}

fn count(slot: &mut (u64, u64), start: u64, limit: u64) -> bool {
    if slot.0 != start {
        *slot = (start, 0);
    }
    if slot.1 >= limit {
        return false;
    }
    slot.1 = slot.1.saturating_add(1);
    true
}

/// The counters of one leader.
#[derive(Debug, Default)]
pub struct Limiter {
    windows: HashMap<(Class, Who), Window>,
}

impl Limiter {
    /// Counts one request; `false` when it is over its limit and must be refused.
    pub fn admit(&mut self, class: Class, who: Who, now: u64) -> bool {
        if self.windows.len() >= KEEP {
            self.windows.retain(|_, w| now.saturating_sub(w.seen) < DAY);
        }
        let w = self.windows.entry((class, who)).or_default();
        let first = w.seen == 0;
        w.seen = now.max(1);
        let minute = now.saturating_sub(now.checked_rem(MINUTE).unwrap_or(0));
        let day = now.saturating_sub(now.checked_rem(DAY).unwrap_or(0));
        match class {
            Class::Commit => {
                let (rate, burst) = COMMIT;
                let full = burst.saturating_mul(1_000);
                if first {
                    w.bucket = (full, now);
                }
                let refill = now.saturating_sub(w.bucket.1).saturating_mul(rate);
                w.bucket = (w.bucket.0.saturating_add(refill).min(full), now);
                if w.bucket.0 < 1_000 {
                    return false;
                }
                w.bucket.0 = w.bucket.0.saturating_sub(1_000);
                true
            }
            Class::Check | Class::Explain => {
                let (per_minute, per_day) = if class == Class::Check {
                    CHECK
                } else {
                    EXPLAIN
                };
                let mut probe = *w;
                let ok = count(&mut probe.minute, minute, per_minute)
                    && count(&mut probe.day, day, per_day);
                if ok {
                    *w = probe;
                }
                ok
            }
            Class::Search => count(&mut w.minute, minute, SEARCH),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who() -> Who {
        Who::Instance(Id([1; 16]))
    }

    // §13.7.4: commit has a burst of 100 and refills 20 per second
    #[test]
    fn commit_bursts_then_refills() {
        let mut l = Limiter::default();
        for _ in 0..100 {
            assert!(l.admit(Class::Commit, who(), 1_000));
        }
        assert!(!l.admit(Class::Commit, who(), 1_000));
        assert!(l.admit(Class::Commit, who(), 1_050));
        assert!(!l.admit(Class::Commit, who(), 1_050));
        assert!(l.admit(Class::Commit, Who::Pep(String::from("pep")), 1_050));
    }

    // §13.7.4: check 60 per minute, explain 30, search 10; a new minute starts over
    #[test]
    fn reads_are_counted_per_minute() {
        let mut l = Limiter::default();
        for (class, n) in [
            (Class::Check, 60),
            (Class::Explain, 30),
            (Class::Search, 10),
        ] {
            for _ in 0..n {
                assert!(l.admit(class, who(), 120_000));
            }
            assert!(!l.admit(class, who(), 179_999));
            assert!(l.admit(class, who(), 180_000));
        }
    }

    // §13.7.4: explain stops at 500 a day across minutes
    #[test]
    fn explain_has_a_daily_limit() {
        let mut l = Limiter::default();
        let mut admitted = 0;
        for minute in 0..20 {
            for _ in 0..30 {
                if l.admit(Class::Explain, who(), 1 + minute * MINUTE) {
                    admitted += 1;
                }
            }
        }
        assert_eq!(admitted, 500);
    }
}
