//! One open-loop run (OP-32, OP-61, OP-158 m.3 (z)).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Semaphore};

use crate::http::{Connection, HttpError, Prepared, requests};
use crate::scenario::{self, Scenario};
use crate::stats::Latencies;

/// How long one request may take before it counts as a timeout.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);

/// What `run` was asked.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Options {
    /// The scenario.
    pub(crate) scenario: &'static Scenario,
    /// `host:port`.
    pub(crate) target: String,
    /// The requests file.
    pub(crate) requests: String,
    /// Arrivals per second.
    pub(crate) rate: u32,
    /// Length of the run in seconds.
    pub(crate) seconds: u32,
    /// Most connections open at once.
    pub(crate) connections: u32,
    /// Where to write the report as well.
    pub(crate) out: Option<String>,
}

impl Options {
    /// Reads `<scenario> <target> --requests <file> [--rate n] [--seconds n] [--connections n]
    /// [--out file]`.
    ///
    /// # Errors
    /// What is wrong with the arguments.
    pub(crate) fn parse(args: &[String]) -> Result<Self, String> {
        let [name, target, rest @ ..] = args else {
            return Err(String::from("run needs a scenario and a target"));
        };
        let scenario = scenario::find(name).ok_or_else(|| format!("unknown scenario {name}"))?;
        let target = target
            .strip_prefix("http://")
            .unwrap_or(target)
            .trim_end_matches('/')
            .to_owned();
        if target.contains('/') || !target.contains(':') {
            return Err(String::from("target is host:port or http://host:port"));
        }
        let mut o = Self {
            scenario,
            target,
            requests: String::new(),
            rate: 100,
            seconds: 10,
            connections: 64,
            out: None,
        };
        let mut it = rest.iter();
        while let Some(flag) = it.next() {
            let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
            let number = || {
                value
                    .parse::<u32>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("{flag} is a positive number"))
            };
            match flag.as_str() {
                "--requests" => o.requests.clone_from(value),
                "--rate" => o.rate = number()?,
                "--seconds" => o.seconds = number()?,
                "--connections" => o.connections = number()?,
                "--out" => o.out = Some(value.clone()),
                _ => return Err(format!("unknown flag {flag}")),
            }
        }
        if o.requests.is_empty() {
            return Err(String::from("--requests is required"));
        }
        Ok(o)
    }
}

#[derive(Default)]
struct Tally {
    latencies: Latencies,
    statuses: BTreeMap<u16, u64>,
    errors: BTreeMap<&'static str, u64>,
}

/// Runs `options` and returns the report.
///
/// # Errors
/// The requests file cannot be read, or the runtime cannot start.
pub(crate) fn main(options: &Options) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(&options.requests)
        .map_err(|_| String::from("cannot read --requests"))?;
    let prepared = requests(&text, options.scenario.path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| String::from("cannot start the runtime"))?;
    Ok(runtime.block_on(drive(options, prepared)))
}

async fn one(
    target: &str,
    idle: &Mutex<Vec<Connection>>,
    req: &Prepared,
) -> Result<u16, HttpError> {
    let reused = idle.lock().await.pop();
    let mut conn = match reused {
        Some(c) => c,
        None => Connection::open(target).await?,
    };
    let status = conn.send(req, TIMEOUT).await?;
    idle.lock().await.push(conn);
    Ok(status)
}

/// The open-loop schedule: request `i` is due at `start + i / rate`; its latency counts from
/// then, waiting for a connection included.
async fn drive(options: &Options, prepared: Vec<Prepared>) -> serde_json::Value {
    let total = u64::from(options.rate).saturating_mul(u64::from(options.seconds));
    let gap = Duration::from_secs(1)
        .checked_div(options.rate)
        .unwrap_or(Duration::ZERO);
    let permits = Arc::new(Semaphore::new(
        usize::try_from(options.connections).unwrap_or(1),
    ));
    let idle = Arc::new(Mutex::new(Vec::new()));
    let tally = Arc::new(Mutex::new(Tally::default()));
    let prepared = Arc::new(prepared);
    let start = tokio::time::Instant::now();
    let wall = Instant::now();
    let mut tasks = Vec::new();
    let mut late = 0u64;
    for i in 0..total {
        let offset = gap.saturating_mul(u32::try_from(i).unwrap_or(u32::MAX));
        let due = start.checked_add(offset).unwrap_or(start);
        tokio::time::sleep_until(due).await;
        if tokio::time::Instant::now().saturating_duration_since(due) > Duration::from_millis(1) {
            late = late.saturating_add(1);
        }
        let (permits, idle, tally, prepared) = (
            Arc::clone(&permits),
            Arc::clone(&idle),
            Arc::clone(&tally),
            Arc::clone(&prepared),
        );
        let target = options.target.clone();
        let which = usize::try_from(i)
            .unwrap_or(0)
            .checked_rem(prepared.len())
            .unwrap_or(0);
        tasks.push(tokio::spawn(async move {
            let Ok(_permit) = permits.acquire().await else {
                return;
            };
            let Some(req) = prepared.get(which) else {
                return;
            };
            let result = one(&target, &idle, req).await;
            let micros = u64::try_from(due.elapsed().as_micros()).unwrap_or(u64::MAX);
            let mut counted = tally.lock().await;
            match result {
                Ok(status) => {
                    counted.latencies.record(micros);
                    let c = counted.statuses.entry(status).or_default();
                    *c = c.saturating_add(1);
                }
                Err(e) => {
                    let k = match e {
                        HttpError::Io => "io",
                        HttpError::Malformed => "malformed",
                        HttpError::Timeout => "timeout",
                    };
                    let c = counted.errors.entry(k).or_default();
                    *c = c.saturating_add(1);
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    let elapsed = wall.elapsed().as_secs_f64();
    let t = tally.lock().await;
    let answered = u64::try_from(t.latencies.len()).unwrap_or(u64::MAX);
    let ok: u64 = t
        .statuses
        .iter()
        .filter(|(s, _)| (200..300).contains(*s))
        .map(|(_, n)| *n)
        .sum();
    #[expect(clippy::cast_precision_loss, reason = "a rate for the report")]
    let throughput = if elapsed > 0.0 {
        answered as f64 / elapsed
    } else {
        0.0
    };
    serde_json::json!({
        "scenario": options.scenario.name,
        "target": options.target,
        "rate_per_s": options.rate,
        "seconds": options.seconds,
        "connections": options.connections,
        "sent": total,
        "answered": answered,
        "ok": ok,
        "statuses": t.statuses.iter().map(|(k, v)| (k.to_string(), serde_json::Value::from(*v))).collect::<serde_json::Map<_, _>>(),
        "errors": t.errors.iter().map(|(k, v)| ((*k).to_owned(), serde_json::Value::from(*v))).collect::<serde_json::Map<_, _>>(),
        "late_starts": late,
        "latency_us": t.latencies.summary(),
        "throughput_per_s": throughput,
        "elapsed_s": elapsed,
        "environment": crate::environment::capture(),
        "open_loop": true,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    // OP-158 m.3 (z)
    #[test]
    fn options_are_read_and_checked() {
        let o = Options::parse(&args(
            "commit http://127.0.0.1:8080/ --requests r.jsonl --rate 50 --seconds 3",
        ))
        .unwrap();
        assert_eq!(o.scenario.name, "commit");
        assert_eq!(o.target, "127.0.0.1:8080");
        assert_eq!((o.rate, o.seconds, o.connections), (50, 3, 64));
        assert!(Options::parse(&args("nope 127.0.0.1:1 --requests r")).is_err());
        assert!(Options::parse(&args("check 127.0.0.1:1")).is_err());
        assert!(Options::parse(&args("check 127.0.0.1:1 --requests r --rate 0")).is_err());
        assert!(Options::parse(&args("check host/path --requests r")).is_err());
    }
}
