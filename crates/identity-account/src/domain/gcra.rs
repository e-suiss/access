//! The generic cell rate algorithm (OP-35, OP-146 m.3): one theoretical arrival time per key.
//! Times are milliseconds of the caller's clock.

/// A rate: one request per `interval_ms`, with bursts of up to `burst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gcra {
    /// Emission interval.
    pub interval_ms: u64,
    /// Requests allowed at once.
    pub burst: u32,
}

/// What the rate allows now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcraDecision {
    /// Allowed; store the new arrival time.
    Allow {
        /// New theoretical arrival time.
        tat_ms: u64,
    },
    /// Over the rate; nothing changes.
    Deny {
        /// Earliest retry, from now.
        retry_after_ms: u64,
    },
}

impl Gcra {
    /// Applies one request at `now_ms` to the stored arrival time.
    #[must_use]
    pub fn check(&self, tat_ms: u64, now_ms: u64) -> GcraDecision {
        let next = tat_ms.max(now_ms).saturating_add(self.interval_ms);
        let limit = self.interval_ms.saturating_mul(u64::from(self.burst));
        let ahead = next.saturating_sub(now_ms);
        if ahead > limit {
            GcraDecision::Deny {
                retry_after_ms: ahead.saturating_sub(limit),
            }
        } else {
            GcraDecision::Allow { tat_ms: next }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-35
    #[test]
    fn burst_then_steady_rate() {
        let g = Gcra {
            interval_ms: 1000,
            burst: 3,
        };
        let mut tat = 0;
        for _ in 0..3 {
            match g.check(tat, 10_000) {
                GcraDecision::Allow { tat_ms } => tat = tat_ms,
                GcraDecision::Deny { .. } => panic!("burst"),
            }
        }
        assert_eq!(
            g.check(tat, 10_000),
            GcraDecision::Deny {
                retry_after_ms: 1000
            }
        );
        assert!(matches!(g.check(tat, 11_000), GcraDecision::Allow { .. }));
        assert!(matches!(
            g.check(tat, 1_000_000),
            GcraDecision::Allow { tat_ms: 1_001_000 }
        ));
    }
}
