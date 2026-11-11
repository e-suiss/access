//! The process lifecycle under an orchestrator (§17.9.3, §17.9.7, OP-50, OP-53, PD): after
//! SIGTERM the server reports not ready, keeps serving for the drain so the load balancer stops
//! sending, then stops accepting and lets in-flight requests finish within the shutdown bound;
//! the pod's grace period covers the preStop sleep, the drain and the shutdown. At a cold start
//! the server is ready only after every realm's issuer and JWKS loaded (it does not start
//! otherwise) and a random start jitter of up to five seconds, so a fleet restart does not
//! arrive at the database at once. Liveness never waits on readiness or on migrations.

use std::time::Duration;

/// The preStop sleep before SIGTERM (OP-50, PD).
pub(crate) const PRE_STOP: Duration = Duration::from_secs(5);

/// How long the server keeps serving after SIGTERM while not ready (OP-50, PD).
pub(crate) const DRAIN: Duration = Duration::from_secs(2);

/// How long in-flight requests may take after the listeners stop accepting (OP-50, PD).
pub(crate) const SHUTDOWN: Duration = Duration::from_secs(15);

/// The pod's termination grace period (OP-50, PD).
pub(crate) const GRACE: Duration = Duration::from_secs(45);

/// The largest start jitter, in milliseconds (OP-53, PD).
pub(crate) const MAX_JITTER_MS: u64 = 5_000;

/// A start jitter in `0..=MAX_JITTER_MS` from the RNG; without randomness, the largest (the
/// slower start is the safe one).
pub(crate) fn jitter() -> Duration {
    let ms = access_crypto::random::bytes::<8>().map_or(MAX_JITTER_MS, |b| {
        u64::from_le_bytes(b) % (MAX_JITTER_MS + 1)
    });
    Duration::from_millis(ms)
}

/// Waits `jitter`, then runs `ready` (OP-53).
pub(crate) async fn ready_after(jitter: Duration, ready: impl FnOnce()) {
    tracing::info!(
        jitter_ms = jitter.as_millis(),
        "ready after the start jitter (OP-53)"
    );
    tokio::time::sleep(jitter).await;
    ready();
}

/// `served`, ended `bound` after `stopped` turns true if in-flight requests are still running
/// then (OP-50).
pub(crate) async fn bounded<F>(
    served: F,
    mut stopped: tokio::sync::watch::Receiver<bool>,
    bound: Duration,
) -> Result<(), String>
where
    F: std::future::Future<Output = Result<(), String>>,
{
    let deadline = async {
        let _ = stopped.wait_for(|s| *s).await;
        tokio::time::sleep(bound).await;
    };
    tokio::select! {
        r = served => r,
        () = deadline => {
            tracing::warn!("in-flight requests outlived the shutdown bound (OP-50)");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-50, OP-53
    #[test]
    fn op_50_the_grace_period_covers_the_stop_and_the_jitter_stays_in_bounds() {
        assert!(PRE_STOP + DRAIN + SHUTDOWN < GRACE);
        for _ in 0..256 {
            assert!(jitter() <= Duration::from_millis(MAX_JITTER_MS));
        }
    }

    // OP-50: the deployment manifests name the server's own bounds
    #[test]
    fn op_50_the_manifests_name_the_servers_bounds() {
        let deploy = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let values = std::fs::read_to_string(deploy.join("helm/access/values.yaml")).unwrap();
        for (key, d) in [
            ("preStopSeconds", PRE_STOP),
            ("drainSeconds", DRAIN),
            ("shutdownSeconds", SHUTDOWN),
            ("terminationGracePeriodSeconds", GRACE),
        ] {
            let line = format!("{key}: {}", d.as_secs());
            assert!(values.lines().any(|l| l.trim() == line), "{line}");
        }
        let k8s = std::fs::read_to_string(deploy.join("k8s/statefulset.yaml")).unwrap();
        let grace = format!("terminationGracePeriodSeconds: {}", GRACE.as_secs());
        assert!(k8s.lines().any(|l| l.trim() == grace));
    }

    // OP-50: a shutdown that outlives its bound ends at the bound
    #[tokio::test]
    async fn op_50_in_flight_requests_end_at_the_shutdown_bound() {
        let bound = Duration::from_millis(50);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let stuck = async {
            std::future::pending::<()>().await;
            Ok(())
        };
        let ended = tokio::spawn(bounded(stuck, stopped, bound));
        tokio::task::yield_now().await;
        let start = tokio::time::Instant::now();
        stop.send(true).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), ended)
                .await
                .unwrap()
                .unwrap(),
            Ok(())
        );
        assert!(start.elapsed() >= bound);
        let (_stop, stopped) = tokio::sync::watch::channel(false);
        let done = bounded(async { Err(String::from("listener")) }, stopped, bound).await;
        assert_eq!(
            done,
            Err(String::from("listener")),
            "a finished serve is its own answer"
        );
    }

    // OP-53
    #[tokio::test]
    async fn op_53_readiness_waits_for_the_start_jitter() {
        let ready = std::sync::atomic::AtomicBool::new(false);
        let delay = Duration::from_millis(30);
        let start = tokio::time::Instant::now();
        ready_after(delay, || {
            ready.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
        assert!(ready.load(std::sync::atomic::Ordering::SeqCst));
        assert!(start.elapsed() >= delay);
    }
}
