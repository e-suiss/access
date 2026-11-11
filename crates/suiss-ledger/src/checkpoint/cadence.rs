//! When a log issues its next checkpoint (T16, CMP-6, OP-38, OP-158 m.3 (c)): every interval
//! or every so many records, whichever comes first, a heartbeat when nothing changed, and an
//! out-of-cycle one on request. Requests that wait together are served by one checkpoint
//! (coalescing).

/// Authority checkpoint interval, milliseconds (T16 POLICY DEFAULT).
pub const INTERVAL_MS: u64 = 60_000;

/// Records after which a checkpoint is due before the interval ends (T16 POLICY DEFAULT).
pub const RECORDS: u64 = 1_000;

/// Why a checkpoint is due now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Due {
    /// None was issued yet.
    First,
    /// The interval passed and records were added.
    Interval,
    /// The interval passed and nothing changed (TI-RT5).
    Heartbeat,
    /// [`RECORDS`] records were added since the last one.
    Records,
    /// A waiting commit asked for one that covers it (SEC23).
    OutOfCycle,
}

/// The cadence of one log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cadence {
    interval_ms: u64,
    records: u64,
    last: Option<(u64, u64)>,
    wanted: Option<u64>,
}

impl Default for Cadence {
    fn default() -> Self {
        Self::new(INTERVAL_MS, RECORDS)
    }
}

impl Cadence {
    /// A cadence of `interval_ms` or `records`, whichever comes first.
    #[must_use]
    pub const fn new(interval_ms: u64, records: u64) -> Self {
        Self {
            interval_ms,
            records,
            last: None,
            wanted: None,
        }
    }

    /// Resumes after the checkpoint of `size` issued at `at`.
    #[must_use]
    pub const fn resume(mut self, size: u64, at: u64) -> Self {
        self.last = Some((size, at));
        self
    }

    /// Asks for an out-of-cycle checkpoint covering at least `size` records. Requests that
    /// arrive before it is issued join the same one (OP-38).
    pub fn want(&mut self, size: u64) {
        let covered = self.last.is_some_and(|(s, _)| s >= size);
        if !covered {
            self.wanted = Some(self.wanted.map_or(size, |w| w.max(size)));
        }
    }

    /// Whether a checkpoint of a log of `size` records is due at `now`.
    #[must_use]
    pub fn due(&self, size: u64, now: u64) -> Option<Due> {
        let Some((last, at)) = self.last else {
            return Some(Due::First);
        };
        if self.wanted.is_some_and(|w| w > last && size >= w) {
            return Some(Due::OutOfCycle);
        }
        if size.saturating_sub(last) >= self.records {
            return Some(Due::Records);
        }
        if now.saturating_sub(at) >= self.interval_ms {
            return Some(if size == last {
                Due::Heartbeat
            } else {
                Due::Interval
            });
        }
        None
    }

    /// A checkpoint of `size` was issued at `at`; the requests it covers are served.
    pub fn issued(&mut self, size: u64, at: u64) {
        self.last = Some((size, at));
        if self.wanted.is_some_and(|w| w <= size) {
            self.wanted = None;
        }
    }

    /// The size and time of the last issued checkpoint.
    #[must_use]
    pub const fn last(&self) -> Option<(u64, u64)> {
        self.last
    }
}
