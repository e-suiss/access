//! Client ID Metadata Document fetches over the guarded outbound client (OP-154 m.1 (d),
//! m.3 (i), §11.3.6): the SSRF guard of [`Outbound`] for the URL and for every URL the
//! document names, no redirect followed, only `200`, the read cut at the limit, one deadline
//! for the fetch and a shorter one for the connection, and the declared rates per URL and per
//! realm. Nothing is cached here: the realm's snapshot is the cache, and a refused fetch writes
//! nothing (§11.3.5).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use access_store::identity::RealmId;

use crate::adapters::outbound::{Outbound, OutboundError};
use crate::domain::cimd::{
    CONNECT_TIMEOUT_MS, FETCH_TIMEOUT_MS, PER_REALM_PER_MINUTE, PER_URL_PER_MINUTE, USER_AGENT,
};
use crate::ports::oauth::{ClientDocuments, Fetch, FetchRefused, Fetched};

const WINDOW: Duration = Duration::from_secs(60);
const MAX_WINDOWS: usize = 16_384;

/// Fixed one-minute windows of fetch counts.
#[derive(Debug, Default)]
struct Windows(HashMap<String, (Instant, u32)>);

impl Windows {
    fn take(&mut self, key: &str, limit: u32, now: Instant) -> bool {
        if self.0.len() >= MAX_WINDOWS {
            self.0
                .retain(|_, (start, _)| now.saturating_duration_since(*start) < WINDOW);
        }
        let entry = self.0.entry(String::from(key)).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }
}

/// The declared rates of CIMD fetches (OP-154 m.3 (i)).
#[derive(Debug, Default)]
pub struct FetchRates {
    urls: Windows,
    realms: Windows,
}

impl FetchRates {
    /// Takes one fetch of `url` for `realm` at `now`; false when either rate is spent.
    pub fn take(&mut self, realm: RealmId, url: &str, now: Instant) -> bool {
        let realm_key = format!("{:x?}", realm.as_bytes());
        if !self.realms.take(&realm_key, PER_REALM_PER_MINUTE, now) {
            return false;
        }
        self.urls.take(url, PER_URL_PER_MINUTE, now)
    }
}

/// CIMD documents and logos over HTTPS.
pub struct HttpClientDocuments {
    outbound: Outbound,
    rates: Mutex<FetchRates>,
}

impl HttpClientDocuments {
    /// Over the operator's trust anchors, with the declared deadlines.
    #[must_use]
    pub fn new(tls: std::sync::Arc<rustls::ClientConfig>) -> Self {
        Self::over(
            Outbound::new(tls, Duration::from_millis(FETCH_TIMEOUT_MS))
                .connecting_within(Duration::from_millis(CONNECT_TIMEOUT_MS)),
        )
    }

    /// Over `outbound`.
    #[must_use]
    pub fn over(outbound: Outbound) -> Self {
        Self {
            outbound,
            rates: Mutex::new(FetchRates::default()),
        }
    }
}

const fn refused(e: OutboundError) -> FetchRefused {
    match e {
        OutboundError::Url => FetchRefused::Url,
        OutboundError::Blocked => FetchRefused::Blocked,
        OutboundError::Unreachable => FetchRefused::Unreachable,
        OutboundError::Malformed => FetchRefused::Malformed,
    }
}

impl ClientDocuments for HttpClientDocuments {
    fn vet<'a>(&'a self, url: &'a str) -> Fetch<'a, ()> {
        Box::pin(async move { self.outbound.vet(url).await.map_err(refused) })
    }

    fn fetch<'a>(
        &'a self,
        realm: RealmId,
        url: &'a str,
        accept: &'a str,
        max_body: usize,
    ) -> Fetch<'a, Fetched> {
        Box::pin(async move {
            let allowed = self
                .rates
                .lock()
                .map(|mut r| r.take(realm, url, Instant::now()))
                .unwrap_or(false);
            if !allowed {
                return Err(FetchRefused::Limited);
            }
            let a = self
                .outbound
                .get_as(url, accept, USER_AGENT, max_body)
                .await
                .map_err(refused)?;
            Ok(Fetched {
                status: a.status,
                max_age_s: a.max_age_s,
                content_type: a.content_type,
                body: a.body,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-154 m.3 (i), Ek B 4536, 4172
    #[test]
    fn fetch_rates_hold_per_url_and_per_realm() {
        let mut r = FetchRates::default();
        let t = Instant::now();
        let a = RealmId::from_bytes([1; 16]);
        for _ in 0..PER_URL_PER_MINUTE {
            assert!(r.take(a, "https://a.example/c", t));
        }
        assert!(!r.take(a, "https://a.example/c", t));
        assert!(r.take(a, "https://a.example/d", t));
        assert!(r.take(a, "https://a.example/c", t + WINDOW));
        let b = RealmId::from_bytes([2; 16]);
        let mut n = 0;
        while r.take(b, &format!("https://b.example/{n}"), t) {
            n += 1;
        }
        assert_eq!(n, PER_REALM_PER_MINUTE);
    }

    // §11.3.6, RFC 6890, Ek B 4535
    #[tokio::test]
    async fn special_purpose_addresses_are_never_fetched() {
        let docs = HttpClientDocuments::over(Outbound::disabled(Duration::from_secs(1)));
        for url in [
            "https://10.0.0.1/client.json",
            "https://169.254.169.254/latest/meta-data",
            "https://[::ffff:127.0.0.1]/client.json",
            "https://127.0.0.1/client.json",
        ] {
            assert_eq!(docs.vet(url).await, Err(FetchRefused::Blocked), "{url}");
        }
        assert_eq!(
            docs.vet("https://app.example:8443/c").await,
            Err(FetchRefused::Blocked)
        );
        assert_eq!(docs.vet("http://app.example/c").await, Err(FetchRefused::Url));
    }
}
