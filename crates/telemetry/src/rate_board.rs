//! The rate limit dashboard's numbers (§12.5.4, TN-127, OP-158 m.3 (v)): for each surface scope
//! (`realm:<slug>` or `platform`) and bucket, the share of the bucket in use now and its 1 h and
//! 24 h averages, the heaviest consumers of the last 24 h and the refusals by type. A bounded
//! per-process table: the scope, bucket and consumer are never metric labels (OP-47), and a
//! consumer is only ever a digest. It is telemetry, never a decision input (TI-18).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

use serde::Serialize;

/// Scopes tracked at once; past it the one seen longest ago is forgotten.
pub const MAX_SCOPES: usize = 4_096;
/// Consumers tracked per scope and hour.
pub const MAX_CONSUMERS: usize = 256;
/// Consumers in a view.
pub const TOP: usize = 10;
/// The share of a bucket in use at or above which the view warns (PD).
pub const THRESHOLD_PERCENT: u8 = 80;

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 3_600_000;
const DAY_MINUTES: u64 = 1_440;

#[derive(Debug, Default)]
struct Bucket {
    now_percent: u8,
    /// The highest share in use in each minute with traffic, newest last.
    minutes: VecDeque<(u64, u8)>,
}

impl Bucket {
    fn record(&mut self, minute: u64, percent: u8) {
        self.now_percent = percent;
        match self.minutes.back_mut() {
            Some((m, p)) if *m == minute => *p = (*p).max(percent),
            _ => self.minutes.push_back((minute, percent)),
        }
        while self
            .minutes
            .front()
            .is_some_and(|(m, _)| minute.saturating_sub(*m) >= DAY_MINUTES)
        {
            self.minutes.pop_front();
        }
    }

    fn average(&self, minute: u64, span: u64) -> u8 {
        let sum: u64 = self
            .minutes
            .iter()
            .filter(|(m, _)| minute.saturating_sub(*m) < span)
            .map(|(_, p)| u64::from(*p))
            .sum();
        u8::try_from(sum.checked_div(span).unwrap_or(0)).unwrap_or(100)
    }
}

#[derive(Debug, Default)]
struct Scope {
    seen_ms: u64,
    buckets: BTreeMap<&'static str, Bucket>,
    /// Requests per consumer digest in each hour, newest last.
    consumers: VecDeque<(u64, HashMap<[u8; 32], u64>)>,
    /// Refusals per type in each minute, newest last.
    events: BTreeMap<&'static str, VecDeque<(u64, u64)>>,
}

impl Scope {
    fn consumer(&mut self, hour: u64, who: [u8; 32]) {
        if self.consumers.back().is_none_or(|(h, _)| *h != hour) {
            self.consumers.push_back((hour, HashMap::new()));
        }
        while self
            .consumers
            .front()
            .is_some_and(|(h, _)| hour.saturating_sub(*h) >= 24)
        {
            self.consumers.pop_front();
        }
        if let Some((_, counts)) = self.consumers.back_mut() {
            if !counts.contains_key(&who) && counts.len() >= MAX_CONSUMERS {
                let least = counts
                    .iter()
                    .min_by_key(|(_, n)| **n)
                    .map(|(k, n)| (*k, *n));
                if let Some((k, n)) = least {
                    counts.remove(&k);
                    counts.insert(who, n);
                }
            }
            let n = counts.entry(who).or_insert(0);
            *n = n.saturating_add(1);
        }
    }

    fn event(&mut self, minute: u64, kind: &'static str) {
        let e = self.events.entry(kind).or_default();
        match e.back_mut() {
            Some((m, n)) if *m == minute => *n = n.saturating_add(1),
            _ => e.push_back((minute, 1)),
        }
        while e
            .front()
            .is_some_and(|(m, _)| minute.saturating_sub(*m) >= DAY_MINUTES)
        {
            e.pop_front();
        }
    }
}

/// One bucket of a view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BucketView {
    /// The bucket's policy name.
    pub name: &'static str,
    /// The share in use at the last request, percent.
    pub now_percent: u8,
    /// The average of each minute's highest share over the last hour, percent.
    pub average_1h_percent: u8,
    /// The same over the last 24 hours.
    pub average_24h_percent: u8,
    /// Whether the share now is at or above [`THRESHOLD_PERCENT`].
    pub above_threshold: bool,
}

/// One consumer of a view: a digest prefix, never an identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConsumerView {
    /// The first 8 bytes of the consumer's digest, hex.
    pub consumer: String,
    /// Requests in the last 24 hours.
    pub requests: u64,
}

/// One refusal type of a view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EventView {
    /// The refusal's problem code.
    pub kind: &'static str,
    /// Refusals in the last hour.
    pub last_hour: u64,
    /// Refusals in the last 24 hours.
    pub last_day: u64,
}

/// What the dashboard shows for one scope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct View {
    /// The buckets, by name.
    pub buckets: Vec<BucketView>,
    /// The heaviest consumers, most first, at most [`TOP`].
    pub top_consumers: Vec<ConsumerView>,
    /// The refusals by type.
    pub events: Vec<EventView>,
    /// The warning threshold, percent.
    pub threshold_percent: u8,
}

/// One request as a bucket saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen<'a> {
    /// `realm:<slug>` or `platform`.
    pub scope: &'a str,
    /// The bucket's policy name.
    pub bucket: &'static str,
    /// The share of the bucket in use after the request, percent.
    pub percent: u8,
    /// The consumer's digest, when the bucket has one.
    pub consumer: Option<[u8; 32]>,
    /// The refusal's problem code, when it was refused.
    pub refused: Option<&'static str>,
}

/// The table.
#[derive(Debug, Default)]
pub struct RateBoard(Mutex<BTreeMap<String, Scope>>);

/// This process's board.
pub static RATE_BOARD: RateBoard = RateBoard(Mutex::new(BTreeMap::new()));

impl RateBoard {
    /// Records one request at `now_ms`.
    pub fn record(&self, seen: Seen<'_>, now_ms: u64) {
        let mut scopes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !scopes.contains_key(seen.scope) && scopes.len() >= MAX_SCOPES {
            let oldest = scopes
                .iter()
                .min_by_key(|(_, s)| s.seen_ms)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                scopes.remove(&k);
            }
        }
        let scope = scopes.entry(seen.scope.to_owned()).or_default();
        scope.seen_ms = now_ms;
        let minute = now_ms / MINUTE_MS;
        scope
            .buckets
            .entry(seen.bucket)
            .or_default()
            .record(minute, seen.percent.min(100));
        if let Some(who) = seen.consumer {
            scope.consumer(now_ms / HOUR_MS, who);
        }
        if let Some(kind) = seen.refused {
            scope.event(minute, kind);
        }
    }

    /// The view of `scope` at `now_ms`.
    #[must_use]
    pub fn view(&self, scope: &str, now_ms: u64) -> View {
        let scopes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(s) = scopes.get(scope) else {
            return View {
                threshold_percent: THRESHOLD_PERCENT,
                ..View::default()
            };
        };
        let (minute, hour) = (now_ms / MINUTE_MS, now_ms / HOUR_MS);
        let buckets = s
            .buckets
            .iter()
            .map(|(name, b)| BucketView {
                name,
                now_percent: b.now_percent,
                average_1h_percent: b.average(minute, 60),
                average_24h_percent: b.average(minute, DAY_MINUTES),
                above_threshold: b.now_percent >= THRESHOLD_PERCENT,
            })
            .collect();
        let mut totals: HashMap<[u8; 32], u64> = HashMap::new();
        for (h, counts) in &s.consumers {
            if hour.saturating_sub(*h) < 24 {
                for (k, n) in counts {
                    let t = totals.entry(*k).or_insert(0);
                    *t = t.saturating_add(*n);
                }
            }
        }
        let mut top: Vec<_> = totals.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let top_consumers = top
            .into_iter()
            .take(TOP)
            .map(|(k, requests)| ConsumerView {
                consumer: k.iter().take(8).fold(String::new(), |mut s, b| {
                    use std::fmt::Write as _;
                    let _ = write!(s, "{b:02x}");
                    s
                }),
                requests,
            })
            .collect();
        let events = s
            .events
            .iter()
            .map(|(kind, e)| {
                let within = |span: u64| {
                    e.iter()
                        .filter(|(m, _)| minute.saturating_sub(*m) < span)
                        .map(|(_, n)| *n)
                        .sum()
                };
                EventView {
                    kind,
                    last_hour: within(60),
                    last_day: within(DAY_MINUTES),
                }
            })
            .collect();
        View {
            buckets,
            top_consumers,
            events,
            threshold_percent: THRESHOLD_PERCENT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(
        bucket: &'static str,
        percent: u8,
        who: u8,
        refused: Option<&'static str>,
    ) -> Seen<'static> {
        Seen {
            scope: "realm:acme",
            bucket,
            percent,
            consumer: Some([who; 32]),
            refused,
        }
    }

    // §12.5.4, TN-127
    #[test]
    fn a_scope_shows_its_buckets_averages_consumers_and_refusals() {
        let board = RateBoard::default();
        let t = 100 * HOUR_MS;
        board.record(seen("realm-write", 40, 1, None), t);
        board.record(seen("realm-write", 90, 1, None), t + MINUTE_MS);
        board.record(
            seen("realm-write", 100, 2, Some("rate-limited")),
            t + MINUTE_MS,
        );
        let v = board.view("realm:acme", t + MINUTE_MS);
        let [b] = v.buckets.as_slice() else {
            panic!("{v:?}")
        };
        assert_eq!((b.now_percent, b.above_threshold), (100, true));
        assert_eq!(b.average_1h_percent, (40 + 100) / 60);
        assert_eq!(v.top_consumers.first().map(|c| c.requests), Some(2));
        assert_eq!(v.top_consumers.len(), 2);
        assert_eq!(
            v.events,
            vec![EventView {
                kind: "rate-limited",
                last_hour: 1,
                last_day: 1
            }]
        );
        let later = board.view("realm:acme", t + 25 * HOUR_MS);
        assert_eq!(later.top_consumers, Vec::new());
        assert_eq!(later.events.first().map(|e| e.last_day), Some(0));
        assert_eq!(board.view("realm:other", t).buckets, Vec::new());
    }
}
