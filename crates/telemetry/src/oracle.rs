//! Advisory `check` / explain volume per Instance for oracle detection (§17.8.2, SEC31).
//!
//! The Instance is never a metric label (OP-47). This is a bounded per-process table of the
//! heaviest requesters over a tumbling window (Space-Saving: at most [`CAPACITY`] entries, each
//! count an upper bound with its possible overcount in `error`), exported to security tooling
//! from the internal listener. It is telemetry, never a decision input (TI-18).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use serde::Serialize;

use crate::signals::ADVISORY_REQUESTS;

/// Most Instances tracked per window.
pub const CAPACITY: usize = 256;
/// Window length (PD): one hour.
pub const WINDOW_MS: u64 = 3_600_000;

/// What was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Advisory {
    /// An advisory `check`.
    Check,
    /// An explain request.
    Explain,
}

impl Advisory {
    const fn label(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Explain => "explain",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    check: u64,
    explain: u64,
    error: u64,
}

impl Entry {
    const fn total(&self) -> u64 {
        self.check.saturating_add(self.explain)
    }
}

#[derive(Debug, Default)]
struct Window {
    start_ms: u64,
    entries: HashMap<Vec<u8>, Entry>,
}

impl Window {
    fn record(&mut self, instance: &[u8], what: Advisory) {
        if !self.entries.contains_key(instance) && self.entries.len() >= CAPACITY {
            let evicted = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.total())
                .map(|(k, e)| (k.clone(), *e));
            if let Some((key, old)) = evicted {
                self.entries.remove(&key);
                self.entries.insert(
                    instance.to_vec(),
                    Entry {
                        check: 0,
                        explain: 0,
                        error: old.total(),
                    },
                );
            }
        }
        let entry = self.entries.entry(instance.to_vec()).or_default();
        match what {
            Advisory::Check => entry.check = entry.check.saturating_add(1),
            Advisory::Explain => entry.explain = entry.explain.saturating_add(1),
        }
    }
}

/// One Instance's volume in a window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Requester {
    /// The Instance id, lowercase hex.
    pub instance: String,
    /// Advisory checks (upper bound).
    pub check: u64,
    /// Explain requests (upper bound).
    pub explain: u64,
    /// Possible overcount from the bounded table.
    pub error: u64,
}

/// The oracle-watch export: the current and the previous window, heaviest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OracleWatch {
    /// Window length in milliseconds.
    pub window_ms: u64,
    /// Start of the current window, Unix milliseconds.
    pub current_start_ms: u64,
    /// The current window.
    pub current: Vec<Requester>,
    /// Start of the previous window, Unix milliseconds.
    pub previous_start_ms: u64,
    /// The previous, complete window.
    pub previous: Vec<Requester>,
}

#[derive(Debug, Default)]
struct Table {
    current: Window,
    previous: Window,
}

impl Table {
    fn roll(&mut self, now_ms: u64) {
        let start = now_ms
            .checked_div(WINDOW_MS)
            .and_then(|w| w.checked_mul(WINDOW_MS))
            .unwrap_or(0);
        if start > self.current.start_ms {
            let previous_start = start.saturating_sub(WINDOW_MS);
            let old = std::mem::take(&mut self.current);
            self.previous = if old.start_ms == previous_start {
                old
            } else {
                Window {
                    start_ms: previous_start,
                    entries: HashMap::new(),
                }
            };
            self.current.start_ms = start;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn ranked(w: &Window) -> Vec<Requester> {
    let mut out: Vec<Requester> = w
        .entries
        .iter()
        .map(|(k, e)| Requester {
            instance: hex(k),
            check: e.check,
            explain: e.explain,
            error: e.error,
        })
        .collect();
    out.sort_by(|a, b| {
        b.check
            .saturating_add(b.explain)
            .cmp(&a.check.saturating_add(a.explain))
            .then_with(|| a.instance.cmp(&b.instance))
    });
    out
}

/// The per-process oracle-watch table.
#[derive(Debug, Default)]
pub struct OracleTable(Mutex<Table>);

impl OracleTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one advisory request of `instance` at `now_ms` (the caller's clock port).
    pub fn record(&self, instance: &[u8], what: Advisory, now_ms: u64) {
        ADVISORY_REQUESTS.incr([what.label()]);
        let mut t = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        t.roll(now_ms);
        t.current.record(instance, what);
    }

    /// The export at `now_ms`.
    #[must_use]
    pub fn snapshot(&self, now_ms: u64) -> OracleWatch {
        let mut t = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        t.roll(now_ms);
        OracleWatch {
            window_ms: WINDOW_MS,
            current_start_ms: t.current.start_ms,
            current: ranked(&t.current),
            previous_start_ms: t.previous.start_ms,
            previous: ranked(&t.previous),
        }
    }
}

/// The process-wide table the authority plane records into.
pub static ORACLE: std::sync::LazyLock<OracleTable> = std::sync::LazyLock::new(OracleTable::new);

#[cfg(test)]
mod tests {
    use super::*;

    // SEC31, §17.8.2: per Instance volume is kept and ranked, heaviest first
    #[test]
    fn heaviest_requesters_come_first() {
        let t = OracleTable::new();
        for _ in 0..5 {
            t.record(b"\x01", Advisory::Check, 10);
        }
        t.record(b"\x02", Advisory::Explain, 20);
        let w = t.snapshot(30);
        assert_eq!(w.current.len(), 2);
        assert_eq!(w.current.first().map(|r| r.instance.as_str()), Some("01"));
        assert_eq!(w.current.first().map(|r| r.check), Some(5));
        assert_eq!(w.current.get(1).map(|r| r.explain), Some(1));
    }

    // SEC31, OP-47: the table is bounded; an evicted slot's count is carried as error
    #[test]
    fn the_table_is_bounded() {
        let t = OracleTable::new();
        for i in 0..(CAPACITY + 10) {
            let key = u32::try_from(i).unwrap_or(u32::MAX).to_be_bytes();
            t.record(&key, Advisory::Check, 1);
        }
        let w = t.snapshot(1);
        assert_eq!(w.current.len(), CAPACITY);
        assert!(w.current.iter().any(|r| r.error > 0));
    }

    // SEC31: windows tumble; the previous complete window stays visible
    #[test]
    fn windows_tumble() {
        let t = OracleTable::new();
        t.record(b"\x01", Advisory::Check, 5);
        let w = t.snapshot(WINDOW_MS + 5);
        assert_eq!(w.current, Vec::new());
        assert_eq!(w.previous.len(), 1);
        let later = t.snapshot(WINDOW_MS.saturating_mul(3));
        assert_eq!(later.previous, Vec::new());
    }
}
