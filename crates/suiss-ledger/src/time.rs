//! Trusted time from independent sources (TI-RT2, TI-19, FA-3, OP-129 m.1): a pure combiner;
//! the driver reads the sources and a monotonic clock.

use alloc::vec::Vec;

/// Declared clock uncertainty U in milliseconds (FA-3, OP-129 m.1, PD).
pub const UNCERTAINTY_MS: u64 = 250;

/// Fewest sources a reading needs (TI-RT2).
pub const MIN_SOURCES: usize = 2;

/// Why no trusted time is available; commit stops (TI-RT2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// The log's time is ahead of a witness's cosignature time by more than U.
    #[error("log time ahead of the witness")]
    AheadOfWitness,
}

/// Cross-check of the log clock against a witness (TI-RT2, OP-140 m.5): a checkpoint whose
/// newest record has `recorded_at` (Unix milliseconds) cannot have been cosigned before that
/// time. The witness reports whole seconds, so its time is read as the end of its second.
///
/// # Errors
/// [`TimeError::AheadOfWitness`] when `recorded_at` is later than the cosignature time plus
/// `uncertainty` milliseconds.
pub const fn check_against_witness(
    recorded_at: u64,
    cosigned_seconds: u64,
    uncertainty: u64,
) -> Result<(), TimeError> {
    let witness_end = cosigned_seconds.saturating_mul(1000).saturating_add(999);
    if recorded_at > witness_end.saturating_add(uncertainty) {
        Err(TimeError::AheadOfWitness)
    } else {
        Ok(())
    }
}

/// One source reading: Unix milliseconds and the source's own declared radius in
/// milliseconds (0 for the process and database clocks; a Roughtime server's `RADI`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Unix milliseconds.
    pub at: u64,
    /// Declared uncertainty of this source, milliseconds.
    pub radius: u64,
}

impl Sample {
    /// A reading with no radius of its own.
    #[must_use]
    pub const fn exact(at: u64) -> Self {
        Self { at, radius: 0 }
    }
}

/// Combines source readings into trusted time and remembers the last one.
#[derive(Clone, Debug)]
pub struct TrustedClock {
    uncertainty: u64,
    last: Option<(u64, u64)>,
    deviating: usize,
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
            deviating: 0,
        }
    }

    /// Trusted time in Unix milliseconds from `samples` (one per source, Unix milliseconds)
    /// read at monotonic time `mono` (milliseconds): the median, the lower one of two.
    ///
    /// # Errors
    /// [`TimeError`]; the caller does not commit.
    pub fn read(&mut self, samples: &[u64], mono: u64) -> Result<u64, TimeError> {
        let samples: Vec<Sample> = samples.iter().copied().map(Sample::exact).collect();
        self.read_samples(&samples, mono)
    }

    /// Trusted time from `samples` with their own radii, read at monotonic time `mono`.
    ///
    /// Two readings agree when they differ by at most U plus both radii. The sources that
    /// agree with each other must be at least [`MIN_SOURCES`] and a strict majority, and that
    /// group must be the only one; the answer is the lower median of its most precise members.
    /// A source outside the group is counted in [`TrustedClock::deviating`] and does not stop
    /// the reading (TI-RT2, FA-3).
    ///
    /// # Errors
    /// [`TimeError`]; the caller does not commit.
    pub fn read_samples(&mut self, samples: &[Sample], mono: u64) -> Result<u64, TimeError> {
        if samples.len() < MIN_SOURCES {
            return Err(TimeError::TooFewSources);
        }
        let group = agreeing(samples, self.uncertainty)?;
        let precise = group.iter().map(|s| s.radius).min().unwrap_or_default();
        let mut values: Vec<u64> = group
            .iter()
            .filter(|s| s.radius == precise)
            .map(|s| s.at)
            .collect();
        values.sort_unstable();
        let mid = values.len().saturating_sub(1) / 2;
        let now = values.get(mid).copied().ok_or(TimeError::TooFewSources)?;
        if let Some((last_now, last_mono)) = self.last {
            let elapsed = mono.checked_sub(last_mono).ok_or(TimeError::Monotonic)?;
            // TI-RT2
            if now.saturating_sub(last_now) > elapsed.saturating_add(self.uncertainty) {
                return Err(TimeError::Jump);
            }
        }
        self.deviating = samples.len().saturating_sub(group.len());
        self.last = Some((now, mono));
        Ok(now)
    }

    /// How many sources the last accepted reading left out.
    #[must_use]
    pub const fn deviating(&self) -> usize {
        self.deviating
    }
}

/// The one strict-majority group of mutually agreeing readings (Marzullo's interval
/// intersection over doubled coordinates, so U splits evenly without rounding).
fn agreeing(samples: &[Sample], uncertainty: u64) -> Result<Vec<Sample>, TimeError> {
    let bound = |s: &Sample| {
        let half = s.radius.saturating_mul(2).saturating_add(uncertainty);
        let mid = s.at.saturating_mul(2);
        (mid.saturating_sub(half), mid.saturating_add(half))
    };
    let mut edges: Vec<(u64, bool)> = Vec::with_capacity(samples.len().saturating_mul(2));
    for s in samples {
        let (lo, hi) = bound(s);
        edges.push((lo, false));
        edges.push((hi, true));
    }
    edges.sort_unstable();
    let (mut depth, mut best, mut regions) = (0_usize, 0_usize, 0_usize);
    let mut at = 0_u64;
    for (x, closes) in edges {
        if closes {
            depth = depth.saturating_sub(1);
            continue;
        }
        depth = depth.saturating_add(1);
        if depth > best {
            (best, regions, at) = (depth, 1, x);
        } else if depth == best {
            regions = regions.saturating_add(1);
        }
    }
    let majority = best.saturating_mul(2) > samples.len();
    if best < MIN_SOURCES || !majority || regions != 1 {
        return Err(TimeError::Disagree);
    }
    Ok(samples
        .iter()
        .copied()
        .filter(|s| {
            let (lo, hi) = bound(s);
            lo <= at && at <= hi
        })
        .collect())
}

#[cfg(test)]
mod tests;
