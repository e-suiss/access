//! The Argon2id service (CR-36, OP-33, OP-146 m.4 (f), §4.10): hashing runs on the blocking
//! pool behind a semaphore of `min(cores, ⌊budget × 0.5 / m⌋)` permits. A request that waits
//! longer than the queue limit is shed with `503 + Retry-After`, so Argon2 never starves the
//! reactor or the other endpoints. The semaphore does not know whether an account exists.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use access_crypto::Secret;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::AccountError;
use crate::domain::legacy;
use crate::domain::password::{
    self, Argon2Params, HashFailure, HashPolicy, Password, Verification,
};
use crate::ports::{LegacyIdp, LegacyIdpUnavailable};

/// CR-36 m.3: the longest wait for a permit.
pub const QUEUE_WAIT: Duration = Duration::from_millis(500);

/// The default `hash_await_warn_time` (§10.2.1 m.3; PD).
pub const AWAIT_WARN: Duration = Duration::from_millis(100);

/// The service's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HasherConfig {
    /// The policy's parameters.
    pub params: Argon2Params,
    /// `max_hash_threads`: concurrent hashes.
    pub permits: usize,
    /// Longest wait for a permit.
    pub queue_wait: Duration,
    /// `hash_await_warn_time`: waits longer than this are logged and counted.
    pub await_warn: Duration,
}

impl HasherConfig {
    /// Sized from the host (OP-146 m.4 (f)): `budget_bytes` from configuration, else the cgroup
    /// limit.
    #[must_use]
    pub fn sized(params: Argon2Params, cores: usize, budget_bytes: Option<u64>) -> Self {
        Self {
            params,
            permits: password::permits(cores, budget_bytes, &params),
            queue_wait: QUEUE_WAIT,
            await_warn: AWAIT_WARN,
        }
    }
}

/// The semaphore's counters (K14).
#[derive(Debug, Default)]
pub struct HashMetrics {
    slow_waits: AtomicU64,
    shed: AtomicU64,
    hashes: AtomicU64,
    waiting: AtomicU64,
    hash_cpu_ns: AtomicU64,
    window: std::sync::Mutex<Option<CpuWindow>>,
}

/// Where the last CPU ratio window started (§17.5.1, OP-32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuWindow {
    /// Process CPU time, nanoseconds.
    pub process_ns: u64,
    /// CPU time spent hashing, nanoseconds.
    pub hash_ns: u64,
}

/// How long one CPU ratio window lasts (§17.5.1; PD).
pub const CPU_WINDOW_NS: u64 = 10_000_000_000;

fn cpu_ns(clock: rustix::time::ClockId) -> u64 {
    let t = rustix::time::clock_gettime(clock);
    u64::try_from(t.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(t.tv_nsec).unwrap_or(0))
}

/// §17.5.1, OP-32: the process's CPU time over the CPU spent hashing between `from` and `to`,
/// in thousandths; `None` when nothing was hashed in between.
#[must_use]
pub fn cpu_ratio_permille(from: CpuWindow, to: CpuWindow) -> Option<u64> {
    let hashed = to.hash_ns.checked_sub(from.hash_ns).filter(|h| *h > 0)?;
    let total = to.process_ns.saturating_sub(from.process_ns);
    total.saturating_mul(1000).checked_div(hashed)
}

impl HashMetrics {
    /// Waits longer than `hash_await_warn_time`.
    #[must_use]
    pub fn slow_waits(&self) -> u64 {
        self.slow_waits.load(Ordering::Relaxed)
    }

    /// Requests shed with 503.
    #[must_use]
    pub fn shed(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }

    /// Hashes computed.
    #[must_use]
    pub fn hashes(&self) -> u64 {
        self.hashes.load(Ordering::Relaxed)
    }

    /// Hashes waiting for a permit now (§17.8.2 Argon2 queue depth).
    #[must_use]
    pub fn waiting(&self) -> u64 {
        self.waiting.load(Ordering::Relaxed)
    }

    /// CPU time spent hashing so far, nanoseconds.
    #[must_use]
    pub fn hash_cpu_ns(&self) -> u64 {
        self.hash_cpu_ns.load(Ordering::Relaxed)
    }

    /// Takes in one hash's CPU time and, once a window has passed, reports
    /// `access_login_cpu_ratio_permille` (§17.5.1, OP-32; target below 1 100).
    fn hashed(&self, cpu: u64) {
        let hash_ns = self
            .hash_cpu_ns
            .fetch_add(cpu, Ordering::Relaxed)
            .saturating_add(cpu);
        let now = CpuWindow {
            process_ns: cpu_ns(rustix::time::ClockId::ProcessCPUTime),
            hash_ns,
        };
        let Ok(mut window) = self.window.lock() else {
            return;
        };
        match *window {
            Some(from) if now.process_ns.saturating_sub(from.process_ns) >= CPU_WINDOW_NS => {
                if let Some(ratio) = cpu_ratio_permille(from, now) {
                    access_telemetry::signals::LOGIN_CPU_RATIO.set_u64(ratio, []);
                }
                *window = Some(now);
            }
            Some(_) => {}
            None => *window = Some(now),
        }
    }

    fn queue(&self, joined: bool) {
        let now = if joined {
            self.waiting
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
        } else {
            self.waiting
                .fetch_sub(1, Ordering::Relaxed)
                .saturating_sub(1)
        };
        // §17.8.2, OP-33
        access_telemetry::signals::ARGON2_QUEUE_DEPTH.set_u64(now, []);
    }
}

/// The password hashing service. [`Hasher::for_policy`] gives a realm's view of it: the same
/// semaphore and counters, hashing under that realm's policy.
pub struct Hasher {
    config: HasherConfig,
    semaphore: Arc<Semaphore>,
    metrics: Arc<HashMetrics>,
    legacy_idp: Option<Arc<dyn LegacyIdp>>,
    policy: Option<HashPolicy>,
}

impl Hasher {
    /// A service with `config.permits` permits.
    #[must_use]
    pub fn new(config: HasherConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.permits.max(1))),
            config,
            metrics: Arc::new(HashMetrics::default()),
            legacy_idp: None,
            policy: None,
        }
    }

    /// This service hashing under a realm's `policy` (§10.2.1, CR-15, CR-36, OP-158 m.3 (y)):
    /// [`Hasher::hash`] and [`Hasher::verify`] then follow it, on the shared semaphore.
    #[must_use]
    pub fn for_policy(&self, policy: HashPolicy) -> Self {
        Self {
            config: self.config,
            semaphore: Arc::clone(&self.semaphore),
            metrics: Arc::clone(&self.metrics),
            legacy_idp: self.legacy_idp.clone(),
            policy: Some(policy),
        }
    }

    /// This service with the previous identity provider of a lazy migration (TN-85).
    #[must_use]
    pub fn with_legacy_idp(mut self, idp: Arc<dyn LegacyIdp>) -> Self {
        self.legacy_idp = Some(idp);
        self
    }

    /// The settings; `permits` is `max_hash_threads`.
    #[must_use]
    pub const fn config(&self) -> &HasherConfig {
        &self.config
    }

    /// The counters.
    #[must_use]
    pub fn metrics(&self) -> &HashMetrics {
        &self.metrics
    }

    async fn permit(&self) -> Result<OwnedSemaphorePermit, AccountError> {
        self.permits(1).await
    }

    /// The permits a hash under `policy` takes: its memory over the configured hash's, at
    /// least one and at most all of them, so a high-memory hash cannot run beside as many
    /// others as a canonical one (CR-36 m.3, OP-158 m.3 (y)).
    fn weight(&self, policy: &HashPolicy) -> u32 {
        let per = |p: &Argon2Params| u64::from(p.m_kib).saturating_mul(u64::from(p.p));
        let base = per(&self.config.params).max(1);
        let need = per(&policy.params_for_permits()).div_ceil(base);
        let all = u64::try_from(self.config.permits.max(1)).unwrap_or(u64::MAX);
        u32::try_from(need.clamp(1, all)).unwrap_or(u32::MAX)
    }

    async fn permits(&self, n: u32) -> Result<OwnedSemaphorePermit, AccountError> {
        let start = tokio::time::Instant::now();
        self.metrics.queue(true);
        let acquired = tokio::time::timeout(
            self.config.queue_wait,
            self.semaphore.clone().acquire_many_owned(n),
        )
        .await;
        self.metrics.queue(false);
        access_telemetry::signals::ARGON2_WAIT.record_duration(start.elapsed(), []);
        let Ok(Ok(permit)) = acquired else {
            self.metrics.shed.fetch_add(1, Ordering::Relaxed);
            return Err(AccountError::Busy);
        };
        let waited = start.elapsed();
        if waited > self.config.await_warn {
            self.metrics.slow_waits.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                waited_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                max_hash_threads = self.config.permits,
                "hash_await_warn_time exceeded"
            );
        }
        Ok(permit)
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, HashFailure> + Send + 'static,
    ) -> Result<T, AccountError> {
        self.run_weighted(1, work).await
    }

    async fn run_weighted<T: Send + 'static>(
        &self,
        weight: u32,
        work: impl FnOnce() -> Result<T, HashFailure> + Send + 'static,
    ) -> Result<T, AccountError> {
        let permit = self.permits(weight).await?;
        let (out, cpu) = tokio::task::spawn_blocking(move || {
            let held = permit;
            let started = cpu_ns(rustix::time::ClockId::ThreadCPUTime);
            let out = work();
            let cpu = cpu_ns(rustix::time::ClockId::ThreadCPUTime).saturating_sub(started);
            drop(held);
            (out, cpu)
        })
        .await
        .map_err(|_| AccountError::Hash(HashFailure::Compute))?;
        let out = out?;
        self.metrics.hashed(cpu);
        self.metrics.hashes.fetch_add(1, Ordering::Relaxed);
        Ok(out)
    }

    /// The PHC string of `password` under the policy's parameters.
    ///
    /// # Errors
    /// [`AccountError::Busy`] when no permit came in time; [`AccountError::Hash`].
    pub async fn hash(
        &self,
        password: &Password,
        salt: [u8; 16],
    ) -> Result<Secret<String>, AccountError> {
        if let Some(policy) = self.policy {
            return self.hash_as(policy, password, salt).await;
        }
        let params = self.config.params;
        let password = password.clone();
        self.run(move || password::hash(&params, &password, &salt))
            .await
    }

    /// Checks `password` against a stored PHC string.
    ///
    /// # Errors
    /// [`AccountError::Busy`]; [`AccountError::Hash`] for a malformed hash.
    pub async fn verify(
        &self,
        password: &Password,
        phc: Secret<String>,
    ) -> Result<Verification, AccountError> {
        if let Some(policy) = self.policy {
            return self.verify_as(policy, password, phc).await;
        }
        let params = self.config.params;
        let password = password.clone();
        self.run(move || password::verify(&password, &phc, &params))
            .await
    }

    /// The PHC string of `password` under a realm's `policy`: Argon2id at its profile or, under
    /// the FIPS crypto profile, PBKDF2-HMAC-SHA-256 (§10.2.1, CR-15, CR-36, OP-158 m.3 (y)).
    ///
    /// # Errors
    /// [`AccountError::Busy`] when no permit came in time; [`AccountError::Hash`].
    pub async fn hash_as(
        &self,
        policy: HashPolicy,
        password: &Password,
        salt: [u8; 16],
    ) -> Result<Secret<String>, AccountError> {
        let password = password.clone();
        self.run_weighted(self.weight(&policy), move || {
            password::hash_with(&policy, &password, &salt)
        })
        .await
    }

    /// Checks `password` against a stored Argon2id or PBKDF2 PHC string under a realm's
    /// `policy`; a hash of the other algorithm or below the policy is to be rehashed (CR-37).
    ///
    /// # Errors
    /// [`AccountError::Busy`]; [`AccountError::Hash`] for a malformed hash.
    pub async fn verify_as(
        &self,
        policy: HashPolicy,
        password: &Password,
        phc: Secret<String>,
    ) -> Result<Verification, AccountError> {
        let stored = password::stored_params(phc.expose())
            .ok()
            .flatten()
            .map_or(HashPolicy::Pbkdf2 { iterations: 0 }, HashPolicy::Argon2);
        let weight = self.weight(&stored);
        let password = password.clone();
        self.run_weighted(weight, move || {
            password::verify_with(&password, &phc, &policy)
        })
        .await
    }

    /// Checks `password` against an imported hash of `algorithm` (TN-85, OP-153 m.11 (h)), on
    /// the same pool and semaphore as Argon2id.
    ///
    /// # Errors
    /// [`AccountError::Busy`]; [`AccountError::Hash`] for a stored text outside its format.
    pub async fn verify_legacy(
        &self,
        algorithm: &str,
        stored: Secret<String>,
        password: &Password,
    ) -> Result<bool, AccountError> {
        let algorithm = algorithm.to_owned();
        let password = password.clone();
        self.run(move || {
            legacy::verify(&algorithm, stored.expose(), &password)
                .map_err(|_| HashFailure::Malformed)
        })
        .await
    }

    /// Asks the previous identity provider (TN-85) while holding a permit, so the path waits
    /// in the same queue. No provider configured is unavailable: the sign-in fails closed.
    ///
    /// # Errors
    /// [`AccountError::Busy`].
    pub async fn ask_legacy_idp(
        &self,
        identifier: &str,
        password: &Password,
        reference: &str,
    ) -> Result<Result<bool, LegacyIdpUnavailable>, AccountError> {
        let permit = self.permit().await?;
        let answer = match &self.legacy_idp {
            Some(idp) => idp.verify(identifier, password.bytes(), reference).await,
            None => Err(LegacyIdpUnavailable),
        };
        drop(permit);
        Ok(answer)
    }

    /// Takes and returns a permit without hashing: the path without a stored hash waits in
    /// the same queue and is shed the same way (CR-36 m.3, MD-18).
    ///
    /// # Errors
    /// [`AccountError::Busy`].
    pub async fn admit(&self) -> Result<(), AccountError> {
        drop(self.permit().await?);
        Ok(())
    }
}

#[cfg(test)]
mod profile_tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::domain::password::HashProfile;

    fn hasher(permits: usize) -> Hasher {
        Hasher::new(HasherConfig {
            permits,
            ..HasherConfig::sized(Argon2Params::CANONICAL, permits, None)
        })
    }

    // CR-36, OP-158
    #[test]
    fn a_high_memory_hash_takes_every_permit() {
        let h = hasher(8);
        assert_eq!(h.weight(&HashPolicy::Argon2(Argon2Params::CANONICAL)), 1);
        assert_eq!(h.weight(&HashPolicy::of(HashProfile::HighMemory, false)), 8);
        assert_eq!(h.weight(&HashPolicy::of(HashProfile::Standard, true)), 1);
    }

    // CR-15, CR-37, OP-158
    #[tokio::test]
    async fn a_fips_realm_hashes_and_verifies_on_the_same_pool() {
        let h = hasher(2);
        let pw = Password::new("correct horse battery").unwrap();
        let fips = HashPolicy::of(HashProfile::Standard, true);
        let salt = access_crypto::random::bytes::<16>().unwrap();
        let phc = h.hash_as(fips, &pw, salt).await.unwrap();
        assert!(phc.expose().starts_with("$pbkdf2-sha256$"));
        let v = h.verify_as(fips, &pw, phc.clone()).await.unwrap();
        assert!(v.matched && !v.rehash);
        let v = h
            .verify_as(HashPolicy::Argon2(Argon2Params::CANONICAL), &pw, phc)
            .await
            .unwrap();
        assert!(v.matched && v.rehash);
        assert_eq!(h.metrics().hashes(), 3);
    }
}

#[cfg(test)]
mod cpu_tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §17.5.1, OP-32
    #[test]
    fn the_ratio_is_process_cpu_over_hash_cpu() {
        let from = CpuWindow {
            process_ns: 1_000,
            hash_ns: 500,
        };
        let to = CpuWindow {
            process_ns: 12_000,
            hash_ns: 10_500,
        };
        assert_eq!(cpu_ratio_permille(from, to), Some(1_100));
        assert_eq!(cpu_ratio_permille(to, to), None);
    }

    // §17.5.1, OP-32
    #[tokio::test]
    async fn hashing_counts_its_cpu_time() {
        let h = Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 1, None));
        let pw = Password::new("correct horse battery").unwrap();
        let salt = access_crypto::random::bytes::<16>().unwrap();
        h.hash(&pw, salt).await.unwrap();
        assert!(
            h.metrics().hash_cpu_ns() > 1_000_000,
            "{}",
            h.metrics().hash_cpu_ns()
        );
    }
}

#[cfg(test)]
mod view_tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::domain::password::HashProfile;

    // CR-15, OP-158
    #[tokio::test]
    async fn a_realm_view_hashes_under_its_policy_on_the_shared_pool() {
        let h = Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 2, None));
        let fips = h.for_policy(HashPolicy::of(HashProfile::Standard, true));
        let pw = Password::new("correct horse battery").unwrap();
        let salt = access_crypto::random::bytes::<16>().unwrap();
        let phc = fips.hash(&pw, salt).await.unwrap();
        assert!(phc.expose().starts_with("$pbkdf2-sha256$i=600000$"));
        assert!(fips.verify(&pw, phc.clone()).await.unwrap().matched);
        assert!(
            h.hash(&pw, salt)
                .await
                .unwrap()
                .expose()
                .starts_with("$argon2id$")
        );
        assert_eq!(
            h.metrics().hashes(),
            3,
            "the view counts on the shared counters"
        );
    }
}
