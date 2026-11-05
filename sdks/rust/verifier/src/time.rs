//! Trusted time for offline verification (OP-150 m.1 (b), T25, U2, §9.12.4): the
//! [`TrustedClock`] port and a sans-I/O [`ClockGuard`] that turns readings into the
//! `now` the Kernel checks horizons against, or refuses.

use access_kernel::model::TrustedTime;

/// Default tolerance between trusted-time progress and monotonic progress, in
/// milliseconds; the declared uncertainty U of FA-3.
pub const DEFAULT_TOLERANCE_MS: u64 = 250;

/// One reading of the device clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockReading {
    /// Signed or otherwise trusted wall time, Unix milliseconds.
    pub trusted: TrustedTime,
    /// Monotonic time since an arbitrary origin that survives no reset, milliseconds.
    pub monotonic_ms: u64,
}

/// Why the verifier has no trusted time; every variant means DENY for offline use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClockError {
    /// The clock did not answer.
    #[error("trusted clock unavailable")]
    Unavailable,
    /// Trusted time is earlier than the last accepted reading.
    #[error("trusted time went back")]
    WentBack,
    /// The monotonic clock is earlier than the last accepted reading.
    #[error("monotonic clock went back")]
    MonotonicWentBack,
    /// Trusted time advanced more than monotonic time plus the tolerance.
    #[error("trusted time jumped ahead")]
    JumpedAhead,
    /// Monotonic time advanced more than trusted time plus the tolerance.
    #[error("trusted time froze")]
    Frozen,
    /// A reading does not fit the time range.
    #[error("time out of range")]
    OutOfRange,
}

/// The device clock port (T25): signed time plus a monotonic clock.
pub trait TrustedClock {
    /// Reads both clocks at once.
    ///
    /// # Errors
    /// [`ClockError::Unavailable`] or [`ClockError::OutOfRange`].
    fn read(&self) -> Result<ClockReading, ClockError>;
}

/// Accepts a reading only when trusted time and monotonic time moved together since the
/// last accepted reading (TI-RT2 applied to the verifier).
#[derive(Clone, Debug)]
pub struct ClockGuard {
    tolerance_ms: u64,
    last: Option<ClockReading>,
}

impl ClockGuard {
    /// A guard with no anchor; the first reading is accepted as is.
    #[must_use]
    pub const fn new(tolerance_ms: u64) -> Self {
        Self {
            tolerance_ms,
            last: None,
        }
    }

    /// A guard anchored at a reading accepted earlier, for example the one in the last
    /// reconciled offline report.
    #[must_use]
    pub const fn anchored(tolerance_ms: u64, last: ClockReading) -> Self {
        Self {
            tolerance_ms,
            last: Some(last),
        }
    }

    /// The last accepted reading.
    #[must_use]
    pub const fn last(&self) -> Option<ClockReading> {
        self.last
    }

    /// Reads `clock` and returns the trusted `now`.
    ///
    /// # Errors
    /// [`ClockError`]; the guard keeps its anchor.
    pub fn now(&mut self, clock: &impl TrustedClock) -> Result<TrustedTime, ClockError> {
        self.accept(clock.read()?)
    }

    /// Checks `reading` against the anchor and makes it the new anchor.
    ///
    /// # Errors
    /// [`ClockError`]; the guard keeps its anchor.
    pub fn accept(&mut self, reading: ClockReading) -> Result<TrustedTime, ClockError> {
        if let Some(last) = self.last {
            let mono = reading
                .monotonic_ms
                .checked_sub(last.monotonic_ms)
                .ok_or(ClockError::MonotonicWentBack)?;
            let trusted = reading
                .trusted
                .checked_sub(last.trusted)
                .ok_or(ClockError::WentBack)?;
            if trusted > mono.saturating_add(self.tolerance_ms) {
                return Err(ClockError::JumpedAhead);
            }
            if mono > trusted.saturating_add(self.tolerance_ms) {
                return Err(ClockError::Frozen);
            }
        }
        self.last = Some(reading);
        Ok(reading.trusted)
    }
}

impl Default for ClockGuard {
    fn default() -> Self {
        Self::new(DEFAULT_TOLERANCE_MS)
    }
}
