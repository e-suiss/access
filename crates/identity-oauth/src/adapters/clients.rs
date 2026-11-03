//! Adapters of the ports that reach a client's own endpoints, over [`Outbound`]: its
//! published keys for `private_key_jwt` (RFC 7523, §11.3.6) and its back-channel logout
//! endpoint (OIDC Back-Channel Logout 1.0 §2.5, §2.8).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::adapters::outbound::{Outbound, OutboundError};
use crate::ports::Unavailable;
use crate::ports::oauth::{ClientKeys, LogoutDelivery, PostFailure};

/// Largest JWKS document read (PD).
pub const MAX_JWKS: usize = 64 * 1024;

/// How long a JWKS document is kept (PD): the client's `max-age` within these bounds, the
/// default without one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachePolicy {
    /// Shortest, seconds.
    pub min_s: u64,
    /// Longest, seconds.
    pub max_s: u64,
    /// Without `max-age`, seconds.
    pub default_s: u64,
    /// Most documents kept.
    pub entries: usize,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            min_s: 60,
            max_s: 3_600,
            default_s: 300,
            entries: 1_024,
        }
    }
}

impl CachePolicy {
    /// How long a document with `max_age_s` is kept.
    #[must_use]
    pub fn keep_s(&self, max_age_s: Option<u64>) -> u64 {
        max_age_s
            .unwrap_or(self.default_s)
            .clamp(self.min_s, self.max_s.max(self.min_s))
    }
}

/// Clients' JWKS documents over HTTPS, cached per URI.
pub struct HttpClientKeys {
    outbound: Outbound,
    policy: CachePolicy,
    cache: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
}

impl HttpClientKeys {
    /// Over `outbound`.
    #[must_use]
    pub fn new(outbound: Outbound, policy: CachePolicy) -> Self {
        Self {
            outbound,
            policy,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, uri: &str) -> Option<Vec<u8>> {
        let cache = self.cache.lock().ok()?;
        cache
            .get(uri)
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(doc, _)| doc.clone())
    }

    fn keep(&self, uri: &str, doc: &[u8], keep_s: u64) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let now = Instant::now();
        if cache.len() >= self.policy.entries {
            cache.retain(|_, (_, until)| now < *until);
            if cache.len() >= self.policy.entries {
                cache.clear();
            }
        }
        if let Some(until) = now.checked_add(Duration::from_secs(keep_s)) {
            cache.insert(String::from(uri), (doc.to_vec(), until));
        }
    }
}

impl ClientKeys for HttpClientKeys {
    async fn fetch(&self, jwks_uri: &str) -> Result<Vec<u8>, Unavailable> {
        if let Some(doc) = self.cached(jwks_uri) {
            return Ok(doc);
        }
        let answer = self
            .outbound
            .get(
                jwks_uri,
                "application/jwk-set+json, application/json",
                MAX_JWKS,
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "client JWKS unavailable");
                Unavailable
            })?;
        if answer.status != 200 {
            tracing::warn!(status = answer.status, "client JWKS refused");
            return Err(Unavailable);
        }
        self.keep(jwks_uri, &answer.body, self.policy.keep_s(answer.max_age_s));
        Ok(answer.body)
    }
}

/// The class of a back-channel answer (OIDC Back-Channel Logout 1.0 §2.8).
///
/// # Errors
/// [`PostFailure`] for anything but `2xx`.
pub fn classify(status: u16, retry_after_s: Option<u64>) -> Result<(), PostFailure> {
    match status {
        200..=299 => Ok(()),
        408 | 425 | 429 | 500 | 502..=599 => Err(PostFailure::Transient {
            retry_after_ms: retry_after_s.and_then(|s| s.checked_mul(1000)),
        }),
        _ => Err(PostFailure::Rejected { status }),
    }
}

/// Logout tokens posted to clients' back-channel endpoints.
pub struct HttpLogoutDelivery {
    outbound: Outbound,
}

impl HttpLogoutDelivery {
    /// Over `outbound`.
    #[must_use]
    pub const fn new(outbound: Outbound) -> Self {
        Self { outbound }
    }
}

impl LogoutDelivery for HttpLogoutDelivery {
    async fn post(&self, uri: &str, logout_token: &str) -> Result<(), PostFailure> {
        if !logout_token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(PostFailure::Refused);
        }
        let form = format!("logout_token={logout_token}");
        match self.outbound.post_form(uri, &form).await {
            Ok(a) => classify(a.status, a.retry_after_s),
            Err(OutboundError::Url | OutboundError::Blocked) => Err(PostFailure::Refused),
            Err(OutboundError::Unreachable | OutboundError::Malformed) => {
                Err(PostFailure::Transient {
                    retry_after_ms: None,
                })
            }
        }
    }
}
