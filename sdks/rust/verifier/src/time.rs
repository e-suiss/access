//! Trusted time for offline verification (OP-150 m.1 (b), T25, U2, §9.12.4): the
//! [`TrustedClock`] port and a sans-I/O [`ClockGuard`] that turns readings into the
//! `now` the Kernel checks horizons against, or refuses.

use access_kernel::model::TrustedTime;

/// Default fixed term of the tolerance between trusted-time progress and monotonic progress,
/// in milliseconds; the declared uncertainty U of FA-3.
pub const DEFAULT_TOLERANCE_MS: u64 = 250;

/// Default proportional term of the tolerance: how far, in parts per million of the monotonic
/// time elapsed since the anchor, the two clocks may drift apart (PD; a quartz oscillator
/// stays within ±100 ppm, the margin doubles it).
pub const DEFAULT_DRIFT_PPM: u64 = 200;

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
    /// A re-anchoring reading is not within the fixed tolerance of the attested time.
    #[error("reading not attested")]
    Unattested,
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
/// anchor, within a fixed term plus a term proportional to the monotonic time elapsed since
/// the anchor, and neither went back since the last accepted reading (TI-RT2, FA-3 applied to
/// the verifier). Measured from the anchor rather than from the last reading, small steps
/// cannot add up to a large jump. A guard that refused stays refused until it is re-anchored
/// on an attested time ([`ClockGuard::reanchor`]).
#[derive(Clone, Debug)]
pub struct ClockGuard {
    tolerance_ms: u64,
    drift_ppm: u64,
    anchor: Option<ClockReading>,
    last: Option<ClockReading>,
}

impl ClockGuard {
    /// A guard with no anchor and [`DEFAULT_DRIFT_PPM`]; the first reading is accepted as is
    /// and becomes the anchor.
    #[must_use]
    pub const fn new(tolerance_ms: u64) -> Self {
        Self {
            tolerance_ms,
            drift_ppm: DEFAULT_DRIFT_PPM,
            anchor: None,
            last: None,
        }
    }

    /// A guard anchored at a reading accepted earlier, for example the one in the last
    /// reconciled offline report.
    #[must_use]
    pub const fn anchored(tolerance_ms: u64, last: ClockReading) -> Self {
        Self {
            tolerance_ms,
            drift_ppm: DEFAULT_DRIFT_PPM,
            anchor: Some(last),
            last: Some(last),
        }
    }

    /// The same guard with the proportional term `drift_ppm`.
    #[must_use]
    pub const fn with_drift(mut self, drift_ppm: u64) -> Self {
        self.drift_ppm = drift_ppm;
        self
    }

    /// The reading the clocks' progress is measured from.
    #[must_use]
    pub const fn anchor(&self) -> Option<ClockReading> {
        self.anchor
    }

    /// How far the clocks may have drifted apart after `elapsed_ms` of monotonic time.
    #[must_use]
    pub fn allowance_ms(&self, elapsed_ms: u64) -> u64 {
        let proportional = elapsed_ms
            .saturating_mul(self.drift_ppm)
            .checked_div(1_000_000)
            .unwrap_or(0);
        self.tolerance_ms.saturating_add(proportional)
    }

    /// Re-anchors the guard on `reading` after a refusal, a reboot or a long suspension: the
    /// reading's trusted time must be within the fixed tolerance of `attested`, a time the
    /// verifier took from an artefact it verified online since (a receipt's `iat`, a witness
    /// cosignature over the domain's checkpoint, TI-RT5), and must not be earlier than the last
    /// accepted reading (TI-19: no backdating). The monotonic clock may have restarted.
    ///
    /// # Errors
    /// [`ClockError::Unattested`] or [`ClockError::WentBack`]; the guard keeps its anchor.
    pub fn reanchor(
        &mut self,
        reading: ClockReading,
        attested: TrustedTime,
    ) -> Result<TrustedTime, ClockError> {
        if reading.trusted.abs_diff(attested) > self.tolerance_ms {
            return Err(ClockError::Unattested);
        }
        if self.last.is_some_and(|l| reading.trusted < l.trusted) {
            return Err(ClockError::WentBack);
        }
        self.anchor = Some(reading);
        self.last = Some(reading);
        Ok(reading.trusted)
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
            if reading.monotonic_ms < last.monotonic_ms {
                return Err(ClockError::MonotonicWentBack);
            }
            if reading.trusted < last.trusted {
                return Err(ClockError::WentBack);
            }
        }
        if let Some(anchor) = self.anchor {
            let mono = reading
                .monotonic_ms
                .checked_sub(anchor.monotonic_ms)
                .ok_or(ClockError::MonotonicWentBack)?;
            let trusted = reading
                .trusted
                .checked_sub(anchor.trusted)
                .ok_or(ClockError::WentBack)?;
            let allowance = self.allowance_ms(mono);
            if trusted > mono.saturating_add(allowance) {
                return Err(ClockError::JumpedAhead);
            }
            if mono > trusted.saturating_add(allowance) {
                return Err(ClockError::Frozen);
            }
        } else {
            self.anchor = Some(reading);
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
