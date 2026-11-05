//! Tamper-evident counter for offline slices (OP-150 m.1 (b), T25, U2, U3, SEC13): the
//! [`TamperEvidentCounter`] port and a sans-I/O [`SliceGuard`] that draws from a slice
//! only while the counter keeps its identity and never goes back.

/// Identity of a provisioned counter; a wiped and re-provisioned counter has a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CounterId(pub [u8; 16]);

/// One reading of the counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterReading {
    /// The counter's identity.
    pub id: CounterId,
    /// Its value; it only grows.
    pub value: u64,
}

/// Why the counter cannot be trusted; every variant means DENY for offline use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CounterError {
    /// The counter did not answer.
    #[error("counter unavailable")]
    Unavailable,
    /// The value is below one seen before.
    #[error("counter rolled back")]
    RolledBack,
    /// The counter has another identity: it was wiped or replaced.
    #[error("counter wiped or replaced")]
    Wiped,
    /// The counter cannot advance by the step.
    #[error("counter out of range")]
    OutOfRange,
}

/// The device counter port (T25): a secure element or TPM monotonic counter, alone or
/// shared by a verifier group (SEC13).
pub trait TamperEvidentCounter {
    /// Reads the counter.
    ///
    /// # Errors
    /// [`CounterError::Unavailable`].
    fn read(&self) -> Result<CounterReading, CounterError>;

    /// Advances the counter by `step` and returns the reading after it.
    ///
    /// # Errors
    /// [`CounterError::Unavailable`] or [`CounterError::OutOfRange`].
    fn advance(&mut self, step: u64) -> Result<CounterReading, CounterError>;
}

/// Outcome of a draw: a decision, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Draw {
    /// The units are drawn; the reading after the draw.
    Granted(CounterReading),
    /// The slice cannot cover the units (DENY).
    Exhausted,
}

/// Draws from one offline slice against a counter (U2, U3).
#[derive(Clone, Debug)]
pub struct SliceGuard {
    base: CounterReading,
    slice: u64,
    last: CounterReading,
}

impl SliceGuard {
    /// A guard for a slice of `slice` units that starts at `base`, the reading recorded
    /// when the slice was granted or last reconciled.
    #[must_use]
    pub const fn new(base: CounterReading, slice: u64) -> Self {
        Self {
            base,
            slice,
            last: base,
        }
    }

    /// The last reading the guard accepted.
    #[must_use]
    pub const fn last(&self) -> CounterReading {
        self.last
    }

    /// Units of the slice already used, by this verifier or by its group.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.last.value.saturating_sub(self.base.value)
    }

    fn check(&self, reading: CounterReading) -> Result<(), CounterError> {
        if reading.id != self.base.id {
            return Err(CounterError::Wiped);
        }
        if reading.value < self.last.value {
            return Err(CounterError::RolledBack);
        }
        Ok(())
    }

    fn within(&self, value: u64) -> bool {
        value
            .checked_sub(self.base.value)
            .is_some_and(|used| used <= self.slice)
    }

    /// Draws `units` from the slice. A group member may see the counter ahead of its own
    /// draws; the slice covers the whole group (SEC13).
    ///
    /// # Errors
    /// [`CounterError`] when the counter cannot be trusted.
    pub fn draw(
        &mut self,
        counter: &mut impl TamperEvidentCounter,
        units: u64,
    ) -> Result<Draw, CounterError> {
        let before = counter.read()?;
        self.check(before)?;
        self.last = before;
        let wanted = before
            .value
            .checked_add(units)
            .ok_or(CounterError::OutOfRange)?;
        if !self.within(wanted) {
            return Ok(Draw::Exhausted);
        }
        let after = counter.advance(units)?;
        self.check(after)?;
        if after.value < wanted {
            return Err(CounterError::RolledBack);
        }
        self.last = after;
        if self.within(after.value) {
            Ok(Draw::Granted(after))
        } else {
            Ok(Draw::Exhausted)
        }
    }
}
