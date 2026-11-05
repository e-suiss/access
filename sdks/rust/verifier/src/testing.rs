//! Emulated clock and counter (OP-150 m.1 (b)): drive horizons, skew, jumps, freezes,
//! outages, rollbacks, wipes and group counters without hardware.

use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

use access_kernel::model::TrustedTime;

use crate::counter::{CounterError, CounterId, CounterReading, TamperEvidentCounter};
use crate::time::{ClockError, ClockReading, TrustedClock};

/// A device clock over an emulated true time.
#[derive(Debug)]
pub struct EmulatedClock {
    truth: Cell<TrustedTime>,
    monotonic: Cell<u64>,
    offset: Cell<i64>,
    frozen: Cell<Option<TrustedTime>>,
    unavailable: Cell<bool>,
}

impl EmulatedClock {
    /// A clock at true time `start` with no skew.
    #[must_use]
    pub const fn new(start: TrustedTime) -> Self {
        Self {
            truth: Cell::new(start),
            monotonic: Cell::new(0),
            offset: Cell::new(0),
            frozen: Cell::new(None),
            unavailable: Cell::new(false),
        }
    }

    /// The emulated true time.
    #[must_use]
    pub fn truth(&self) -> TrustedTime {
        self.truth.get()
    }

    /// Lets `ms` pass: true time and the monotonic clock advance together.
    pub fn advance(&self, ms: u64) {
        self.truth.set(self.truth.get().saturating_add(ms));
        self.monotonic.set(self.monotonic.get().saturating_add(ms));
    }

    /// Sets how far the device's trusted time is from true time; negative is behind.
    pub fn set_skew(&self, offset_ms: i64) {
        self.offset.set(offset_ms);
    }

    /// Moves the device's trusted time by `delta_ms` without the monotonic clock.
    pub fn jump(&self, delta_ms: i64) {
        self.offset.set(self.offset.get().saturating_add(delta_ms));
    }

    /// Stops the device's trusted time at its current value.
    ///
    /// # Errors
    /// [`ClockError::OutOfRange`] when the skew puts the time out of range.
    pub fn freeze(&self) -> Result<(), ClockError> {
        let now = self.device_time()?;
        self.frozen.set(Some(now));
        Ok(())
    }

    /// Lets the device's trusted time follow true time again.
    pub fn thaw(&self) {
        self.frozen.set(None);
    }

    /// Restarts the monotonic clock from zero, as a reset without a secure clock does.
    pub fn reset_monotonic(&self) {
        self.monotonic.set(0);
    }

    /// Makes the clock answer or not.
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.set(unavailable);
    }

    fn device_time(&self) -> Result<TrustedTime, ClockError> {
        if let Some(t) = self.frozen.get() {
            return Ok(t);
        }
        self.truth
            .get()
            .checked_add_signed(self.offset.get())
            .ok_or(ClockError::OutOfRange)
    }
}

impl TrustedClock for EmulatedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.unavailable.get() {
            return Err(ClockError::Unavailable);
        }
        Ok(ClockReading {
            trusted: self.device_time()?,
            monotonic_ms: self.monotonic.get(),
        })
    }
}

#[derive(Debug)]
struct CounterState {
    id: CounterId,
    value: u64,
    unavailable: bool,
}

/// A tamper-evident counter; [`EmulatedCounter::share`] hands the same counter to another
/// member of a verifier group (SEC13).
#[derive(Debug)]
pub struct EmulatedCounter {
    state: Rc<RefCell<CounterState>>,
}

impl EmulatedCounter {
    /// A provisioned counter with identity `id` at zero.
    #[must_use]
    pub fn new(id: CounterId) -> Self {
        Self {
            state: Rc::new(RefCell::new(CounterState {
                id,
                value: 0,
                unavailable: false,
            })),
        }
    }

    /// Another handle on the same counter, for a second group member.
    #[must_use]
    pub fn share(&self) -> Self {
        Self {
            state: Rc::clone(&self.state),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut CounterState) -> T) -> Result<T, CounterError> {
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| CounterError::Unavailable)?;
        Ok(f(&mut state))
    }

    /// Sets the value back to `value`, as an attacker restoring old storage would.
    ///
    /// # Errors
    /// [`CounterError::Unavailable`] when the state is in use.
    pub fn roll_back(&self, value: u64) -> Result<(), CounterError> {
        self.with(|s| s.value = value)
    }

    /// Wipes and re-provisions the counter: identity `id`, value zero.
    ///
    /// # Errors
    /// [`CounterError::Unavailable`] when the state is in use.
    pub fn wipe(&self, id: CounterId) -> Result<(), CounterError> {
        self.with(|s| {
            s.id = id;
            s.value = 0;
        })
    }

    /// Makes the counter answer or not.
    ///
    /// # Errors
    /// [`CounterError::Unavailable`] when the state is in use.
    pub fn set_unavailable(&self, unavailable: bool) -> Result<(), CounterError> {
        self.with(|s| s.unavailable = unavailable)
    }
}

impl TamperEvidentCounter for EmulatedCounter {
    fn read(&self) -> Result<CounterReading, CounterError> {
        self.with(|s| {
            if s.unavailable {
                Err(CounterError::Unavailable)
            } else {
                Ok(CounterReading {
                    id: s.id,
                    value: s.value,
                })
            }
        })?
    }

    fn advance(&mut self, step: u64) -> Result<CounterReading, CounterError> {
        self.with(|s| {
            if s.unavailable {
                return Err(CounterError::Unavailable);
            }
            s.value = s.value.checked_add(step).ok_or(CounterError::OutOfRange)?;
            Ok(CounterReading {
                id: s.id,
                value: s.value,
            })
        })?
    }
}
