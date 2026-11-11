//! The identity plane's degraded-mode watch (OP-45, §17.7.2, OP-158 m.3 (s)). Once a second the
//! identity database is asked whether it answers. While it does not, the process is in degraded
//! mode: the routes answer `503 + Retry-After` and introspection `active=false` on their own; this
//! watch only makes the state visible. `access_identity_degraded_seconds` counts the seconds
//! without an answer, which the alarms read (0–60 s alarm, > 300 s sev-1; PD), and the start and
//! end are logged. Nothing here lets anything through.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use access_store::Pool;
use access_telemetry::signals::IDENTITY_DEGRADED;

/// How often the database is asked.
pub(crate) const PROBE: Duration = Duration::from_secs(1);

/// What one probe changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// Degraded mode began.
    Entered,
    /// Degraded mode ended after this long.
    Exited(Duration),
    /// Nothing changed.
    Same,
}

/// The watch's state: since when the database has not answered.
#[derive(Debug, Default)]
pub(crate) struct Watch {
    since: Option<Instant>,
}

impl Watch {
    /// Takes one probe's answer at `now`.
    pub(crate) fn observe(&mut self, answered: bool, now: Instant) -> Change {
        match (self.since, answered) {
            (None, false) => {
                self.since = Some(now);
                Change::Entered
            }
            (Some(at), true) => {
                self.since = None;
                Change::Exited(now.saturating_duration_since(at))
            }
            _ => Change::Same,
        }
    }

    /// Whole seconds without an answer at `now`; 0 while it answers.
    pub(crate) fn seconds(&self, now: Instant) -> u64 {
        self.since
            .map_or(0, |at| now.saturating_duration_since(at).as_secs())
    }
}

/// Watches `pool` until the process ends; the second value is the seconds without an answer,
/// as the gauge shows them.
pub(crate) fn spawn(pool: Pool) -> (tokio::task::JoinHandle<()>, Arc<AtomicU64>) {
    let shown = Arc::new(AtomicU64::new(0));
    let seconds = Arc::clone(&shown);
    let task = tokio::spawn(async move {
        let mut watch = Watch::default();
        let mut tick = tokio::time::interval(PROBE);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let answered = tokio::time::timeout(PROBE, access_store::connect::ping(&pool))
                .await
                .unwrap_or(false);
            let now = Instant::now();
            match watch.observe(answered, now) {
                Change::Entered => tracing::warn!(
                    event = "identity.degraded.entered",
                    dependency = "database",
                    "identity database unreachable: degraded mode, no new sign-in, refresh or revocation (OP-45)"
                ),
                Change::Exited(d) => tracing::info!(
                    event = "identity.degraded.exited",
                    duration_s = d.as_secs(),
                    "identity database answers again: degraded mode ended (OP-45)"
                ),
                Change::Same => {}
            }
            let s = watch.seconds(now);
            seconds.store(s, Ordering::Relaxed);
            IDENTITY_DEGRADED.set_u64(s, []);
        }
    });
    (task, shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-45, §17.7.2, OP-158 m.3 (s), Ek B 5899
    #[test]
    fn the_watch_counts_the_seconds_without_an_answer_and_logs_each_edge_once() {
        let t0 = Instant::now();
        let mut w = Watch::default();
        assert_eq!(w.observe(true, t0), Change::Same);
        assert_eq!(w.seconds(t0), 0);
        assert_eq!(w.observe(false, t0), Change::Entered);
        let t61 = t0 + Duration::from_secs(61);
        assert_eq!(w.observe(false, t61), Change::Same);
        assert_eq!(w.seconds(t61), 61);
        let t301 = t0 + Duration::from_secs(301);
        assert_eq!(w.seconds(t301), 301);
        assert_eq!(
            w.observe(true, t301),
            Change::Exited(Duration::from_secs(301))
        );
        assert_eq!(w.seconds(t301), 0);
    }

    // OP-45, OP-158 m.3 (t), Ek B 5899
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cut_off_database_raises_the_degraded_seconds_and_its_return_clears_them() {
        let db = access_store::testing::fresh().await.unwrap();
        let (_watch, shown) = spawn(db.app.clone());
        let read = || shown.load(Ordering::Relaxed);
        access_store::testing::refuse_connections(&db, true)
            .await
            .unwrap();
        let start = Instant::now();
        while read() < 2 {
            assert!(start.elapsed() < Duration::from_secs(60), "never degraded");
            tokio::time::sleep(PROBE).await;
        }
        access_store::testing::refuse_connections(&db, false)
            .await
            .unwrap();
        let start = Instant::now();
        while read() != 0 {
            assert!(start.elapsed() < Duration::from_secs(60), "never cleared");
            tokio::time::sleep(PROBE).await;
        }
    }
}
