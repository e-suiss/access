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
use crate::domain::password::{self, Argon2Params, HashFailure, Password, Verification};
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

/// The password hashing service.
pub struct Hasher {
    config: HasherConfig,
    semaphore: Arc<Semaphore>,
    metrics: HashMetrics,
    legacy_idp: Option<Arc<dyn LegacyIdp>>,
}

impl Hasher {
    /// A service with `config.permits` permits.
    #[must_use]
    pub fn new(config: HasherConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.permits.max(1))),
            config,
            metrics: HashMetrics::default(),
            legacy_idp: None,
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
    pub const fn metrics(&self) -> &HashMetrics {
        &self.metrics
    }

    async fn permit(&self) -> Result<OwnedSemaphorePermit, AccountError> {
        let start = tokio::time::Instant::now();
        self.metrics.queue(true);
        let acquired = tokio::time::timeout(
            self.config.queue_wait,
            self.semaphore.clone().acquire_owned(),
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
        let permit = self.permit().await?;
        let out = tokio::task::spawn_blocking(move || {
            let held = permit;
            let out = work();
            drop(held);
            out
        })
        .await
        .map_err(|_| AccountError::Hash(HashFailure::Compute))??;
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
        let params = self.config.params;
        let password = password.clone();
        self.run(move || password::verify(&password, &phc, &params))
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
