//! Trusted time from independent sources (TI-RT2, TI-19, FA-3, OP-129 m.1): a pure combiner;
//! the driver reads the sources and a monotonic clock.

use alloc::vec::Vec;

/// Declared clock uncertainty U in milliseconds (FA-3, OP-129 m.1, PD).
pub const UNCERTAINTY_MS: u64 = 250;

/// Fewest sources a reading needs (TI-RT2).
pub const MIN_SOURCES: usize = 2;

/// Why no trusted time is available; commit stops (TI-RT2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
    /// Fewer than [`MIN_SOURCES`] sources answered.
    #[error("too few time sources")]
    TooFewSources,
    /// The sources differ by more than U.
    #[error("time sources disagree")]
    Disagree,
    /// Time advanced more than the monotonic clock plus U since the last reading.
    #[error("time jumped ahead of the monotonic clock")]
    Jump,
    /// The monotonic clock went back.
    #[error("monotonic clock went back")]
    Monotonic,
}

/// Combines source readings into trusted time and remembers the last one.
#[derive(Clone, Debug)]
pub struct TrustedClock {
    uncertainty: u64,
    last: Option<(u64, u64)>,
}

impl Default for TrustedClock {
    fn default() -> Self {
        Self::new(UNCERTAINTY_MS)
    }
}

impl TrustedClock {
    /// A combiner with uncertainty `uncertainty` milliseconds.
    #[must_use]
    pub const fn new(uncertainty: u64) -> Self {
        Self {
            uncertainty,
            last: None,
        }
    }

    /// Trusted time in Unix milliseconds from `samples` (one per source, Unix milliseconds)
    /// read at monotonic time `mono` (milliseconds): the median, the lower one of two.
    ///
    /// # Errors
    /// [`TimeError`]; the caller does not commit.
    pub fn read(&mut self, samples: &[u64], mono: u64) -> Result<u64, TimeError> {
        if samples.len() < MIN_SOURCES {
            return Err(TimeError::TooFewSources);
        }
        let mut sorted: Vec<u64> = samples.to_vec();
        sorted.sort_unstable();
        let (Some(&low), Some(&high)) = (sorted.first(), sorted.last()) else {
            return Err(TimeError::TooFewSources);
        };
        if high.saturating_sub(low) > self.uncertainty {
            return Err(TimeError::Disagree);
        }
        let mid = sorted.len().saturating_sub(1) / 2;
        let now = sorted.get(mid).copied().ok_or(TimeError::TooFewSources)?;
        if let Some((last_now, last_mono)) = self.last {
            let elapsed = mono.checked_sub(last_mono).ok_or(TimeError::Monotonic)?;
            // TI-RT2: Δrecorded_at ≤ Δmonotonic + U
            if now.saturating_sub(last_now) > elapsed.saturating_add(self.uncertainty) {
                return Err(TimeError::Jump);
            }
        }
        self.last = Some((now, mono));
        Ok(now)
    }
}

#[cfg(test)]
mod tests;
