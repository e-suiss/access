//! Adaptive delay (MD-18, CR-36 m.4, TN-83): no dummy Argon2. A failed attempt is answered no
//! sooner than the running mean of successful ones, whether the account exists or not.

/// The running mean of successful attempt durations, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuccessMean {
    mean_ms: u64,
}

/// Longest duration the mean takes in, so slow outliers cannot stretch every failure.
pub const SAMPLE_CAP_MS: u64 = 2_000;

impl SuccessMean {
    /// A mean seeded from calibration (OP-146 m.4 (f)), used until real successes arrive.
    #[must_use]
    pub const fn seeded(mean_ms: u64) -> Self {
        Self { mean_ms }
    }

    /// The mean.
    #[must_use]
    pub const fn mean_ms(&self) -> u64 {
        self.mean_ms
    }

    /// Takes in one success: an exponential mean with weight 1/8.
    pub fn record(&mut self, duration_ms: u64) {
        let sample = duration_ms.min(SAMPLE_CAP_MS);
        self.mean_ms = self
            .mean_ms
            .saturating_mul(7)
            .saturating_add(sample)
            .checked_div(8)
            .unwrap_or(sample);
    }

    /// How long a failure that took `elapsed_ms` waits before it is answered.
    #[must_use]
    pub const fn pad(&self, elapsed_ms: u64) -> u64 {
        self.mean_ms.saturating_sub(elapsed_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-36, MD-18
    #[test]
    fn failures_wait_for_the_mean() {
        let mut m = SuccessMean::seeded(80);
        assert_eq!(m.pad(30), 50);
        assert_eq!(m.pad(500), 0);
        m.record(160);
        assert_eq!(m.mean_ms(), 90);
        for _ in 0..200 {
            m.record(u64::MAX);
        }
        assert!(m.mean_ms() <= SAMPLE_CAP_MS);
    }
}
