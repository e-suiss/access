//! SPIFFE bundles over the realm's rows and the guarded outbound client (OP-154 m.1 (d),
//! m.3 (r)): a Bundle Endpoint is fetched with the SSRF guard of [`Outbound`], no redirect, only
//! `200`, the read cut at [`MAX_BUNDLE`], one deadline for the fetch and a shorter one for the
//! connection. The bundle is kept per realm and trust domain.

use std::time::Duration;

use access_identity_attest::domain::bundle::MAX_BUNDLE;
use access_identity_attest::ports::{Bundles, Kept, Pending, Scope, Unavailable};
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::workloads::{KeptBundle, keep_bundle, kept_bundle};

use crate::adapters::outbound::Outbound;

/// The `User-Agent` of a Bundle Endpoint fetch.
pub const USER_AGENT: &str = "Suiss-Access-SPIFFE/1";

/// Longest a Bundle Endpoint fetch may take, milliseconds (PD).
pub const FETCH_TIMEOUT_MS: u64 = 5_000;

/// Longest the connection of a fetch may take, milliseconds (PD).
pub const CONNECT_TIMEOUT_MS: u64 = 2_000;

/// The realm's bundles in PostgreSQL, fetched over HTTPS.
pub struct PgBundles {
    app: Pool,
    outbound: Outbound,
}

impl PgBundles {
    /// Over the application pool and the operator's outbound client, with the declared
    /// deadlines.
    #[must_use]
    pub fn new(app: Pool, outbound: Outbound) -> Self {
        Self {
            app,
            outbound: outbound
                .within(Duration::from_millis(FETCH_TIMEOUT_MS))
                .connecting_within(Duration::from_millis(CONNECT_TIMEOUT_MS)),
        }
    }

    async fn begin(&self, scope: Scope) -> Result<TenantTx, Unavailable> {
        TenantTx::begin(
            &self.app,
            TenantId::from_bytes(scope.tenant),
            RealmId::from_bytes(scope.realm),
        )
        .await
        .map_err(|_| Unavailable)
    }
}

impl Bundles for PgBundles {
    fn kept<'a>(&'a self, realm: Scope, trust_domain: &'a str) -> Pending<'a, Option<Kept>> {
        Box::pin(async move {
            let mut t = self.begin(realm).await?;
            let k = kept_bundle(&mut t, trust_domain)
                .await
                .map_err(|_| Unavailable)?;
            t.commit().await.map_err(|_| Unavailable)?;
            Ok(k.map(|k| Kept {
                endpoint: k.bundle_endpoint,
                document: k.document,
                fetched_ms: k.fetched_ms,
            }))
        })
    }

    fn keep<'a>(&'a self, realm: Scope, trust_domain: &'a str, kept: Kept) -> Pending<'a, ()> {
        Box::pin(async move {
            let mut t = self.begin(realm).await?;
            keep_bundle(
                &mut t,
                trust_domain,
                &KeptBundle {
                    bundle_endpoint: kept.endpoint,
                    document: kept.document,
                    fetched_ms: kept.fetched_ms,
                },
            )
            .await
            .map_err(|_| Unavailable)?;
            t.commit().await.map_err(|_| Unavailable)
        })
    }

    fn fetch<'a>(&'a self, endpoint: &'a str) -> Pending<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            if self.outbound.vet(endpoint).await.is_err() {
                return Ok(None);
            }
            match self
                .outbound
                .get_as(endpoint, "application/json", USER_AGENT, MAX_BUNDLE)
                .await
            {
                Ok(a) if a.status == 200 => Ok(Some(a.body)),
                Ok(_) | Err(_) => Ok(None),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-154 m.1 (d), §11.3.6, RFC 6890
    #[tokio::test]
    async fn bundle_endpoints_on_special_purpose_addresses_are_never_fetched() {
        let pool = access_store::Pool::connect_lazy("postgres://localhost/unused").unwrap();
        let b = PgBundles::new(pool, Outbound::disabled(Duration::from_secs(1)));
        for url in [
            "https://10.0.0.1/bundle.json",
            "https://169.254.169.254/latest/meta-data",
            "https://127.0.0.1/bundle.json",
            "http://bundle.example/bundle.json",
            "https://bundle.example:8443/bundle.json",
        ] {
            assert_eq!(b.fetch(url).await.unwrap(), None, "{url}");
        }
    }
}
