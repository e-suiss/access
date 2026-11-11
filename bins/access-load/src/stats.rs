//! Latency and throughput figures (OP-61): exact percentiles of every recorded latency.

/// Latencies in microseconds, kept until summarised.
#[derive(Clone, Debug, Default)]
pub(crate) struct Latencies(Vec<u64>);

impl Latencies {
    /// Records one latency.
    pub(crate) fn record(&mut self, micros: u64) {
        self.0.push(micros);
    }

    /// Number recorded.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The nearest-rank percentile of what was recorded, `milli` in thousandths of a percent
    /// (99.9 % is `99_900`); `None` when empty or out of `1..=100_000`.
    #[must_use]
    pub(crate) fn percentile(&self, milli: u64) -> Option<u64> {
        let mut sorted = self.0.clone();
        sorted.sort_unstable();
        let n = u64::try_from(sorted.len()).ok()?;
        if n == 0 || !(1..=100_000).contains(&milli) {
            return None;
        }
        let rank = milli.checked_mul(n)?.div_ceil(100_000).clamp(1, n);
        sorted
            .get(usize::try_from(rank.saturating_sub(1)).ok()?)
            .copied()
    }

    /// `{p50, p90, p99, p999, max}` in microseconds.
    #[must_use]
    pub(crate) fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "p50": self.percentile(50_000),
            "p90": self.percentile(90_000),
            "p99": self.percentile(99_000),
            "p999": self.percentile(99_900),
            "max": self.percentile(100_000),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-61
    #[test]
    fn percentiles_are_nearest_rank() {
        let mut l = Latencies::default();
        for v in (1..=1000).rev() {
            l.record(v);
        }
        assert_eq!(l.percentile(50_000), Some(500));
        assert_eq!(l.percentile(99_000), Some(990));
        assert_eq!(l.percentile(99_900), Some(999));
        assert_eq!(l.percentile(100_000), Some(1000));
        assert_eq!(Latencies::default().percentile(99_000), None);
        assert_eq!(l.percentile(0), None);
    }
}
