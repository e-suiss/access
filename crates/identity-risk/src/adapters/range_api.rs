//! The k-anonymity range API (IDP-3, OP-151 m.3 (o)): `GET {base}/range/{prefix}`, the first
//! five hex characters of the password's SHA-1 in the HIBP format. Only the prefix leaves the
//! process. Any failure, a status other than 200, a slow answer or a body that is not text is
//! unavailable, never "not breached" (G50).

use std::time::Duration;

use access_identity_account::ports::{BreachRanges, RangeUnavailable};

use crate::ports::RangeFetch;

/// The deadline of one range request (OP-151 m.3 (o)).
pub const TIMEOUT: Duration = Duration::from_secs(2);

/// Largest range body read; real ranges are tens of KiB.
pub const MAX_RANGE_BYTES: usize = 1 << 20;

/// The range API at `base`.
pub struct RangeApi<F> {
    base: String,
    fetch: F,
    timeout: Duration,
}

/// The base URL is not `https`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the range API base must be an https URL without query or fragment")]
pub struct InvalidBase;

impl<F> RangeApi<F> {
    /// The API at `base` (`https://…`, no query or fragment) through `fetch`.
    ///
    /// # Errors
    /// [`InvalidBase`].
    pub fn new(base: &str, fetch: F) -> Result<Self, InvalidBase> {
        let rest = base.strip_prefix("https://").ok_or(InvalidBase)?;
        if rest.is_empty() || base.contains(['?', '#', '@']) || base.len() > 1024 {
            return Err(InvalidBase);
        }
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            fetch,
            timeout: TIMEOUT,
        })
    }

    /// This API with another deadline.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The URL of range `prefix`.
    #[must_use]
    pub fn url(&self, prefix: &str) -> String {
        format!("{}/range/{prefix}", self.base)
    }
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.len() == 5
        && prefix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

impl<F: RangeFetch> BreachRanges for RangeApi<F> {
    async fn range(&self, prefix: &str) -> Result<String, RangeUnavailable> {
        if !valid_prefix(prefix) {
            return Err(RangeUnavailable);
        }
        let url = self.url(prefix);
        let answer = tokio::time::timeout(self.timeout, self.fetch.get(&url, MAX_RANGE_BYTES))
            .await
            .map_err(|_| RangeUnavailable)?
            .map_err(|_| RangeUnavailable)?;
        if answer.status != 200 {
            return Err(RangeUnavailable);
        }
        String::from_utf8(answer.body).map_err(|_| RangeUnavailable)
    }
}
