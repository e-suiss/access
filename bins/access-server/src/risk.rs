//! The SL2 risk sources of this process (TN-46, OP-151 m.1 (b), m.3 (o)): the MMDB GeoIP/ASN
//! file, the breach range API through the SSRF-guarded outbound client or a local mirror, and the
//! cell's address pseudonym key in the token. A source that is not configured answers
//! `unavailable` and the management surface states it.

use std::path::Path;
use std::sync::Arc;

use access_crypto::ip_pseudonym::{IpPseudonymKey, LABEL};
use access_identity_account::adapters::hibp::MirrorRanges;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_risk::adapters::mmdb::MmdbGeo;
use access_identity_risk::adapters::range_api::RangeApi;
use access_identity_risk::adapters::{
    KeyedPseudonyms, NoBreachSource, NoGeoSource, NoPseudonyms, RangeProbe,
};
use access_identity_risk::ports::{Fetched, IpPseudonyms, NoAnswer, RangeFetch};
use access_identity_session::app::RiskServices;
use access_store::Pool;
use access_store::locks::cell_lock;
use suiss_crypto::pkcs11::KeyStore;

use crate::config::Config;

/// `GET` through the outbound client: `https` on 443 to public addresses only (§14.3).
pub(crate) struct OutboundFetch(pub(crate) Outbound);

impl RangeFetch for OutboundFetch {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_body: usize,
    ) -> Result<Fetched, NoAnswer> {
        let a = self
            .0
            .get_with(url, "text/plain", headers, max_body)
            .await
            .map_err(|_| NoAnswer)?;
        Ok(Fetched {
            status: a.status,
            body: a.body,
        })
    }
}

/// The cell's address pseudonym key, made in the token on first use under the cell lock, like
/// the opaque-id root (OP-137). `None` when the token refuses: no address is kept then.
async fn pseudonyms(app: &Pool, keys: &KeyStore) -> Arc<dyn IpPseudonyms> {
    if let Ok(mac) = keys.mac(LABEL) {
        return Arc::new(KeyedPseudonyms(IpPseudonymKey::token(mac)));
    }
    let made = async {
        let lock = cell_lock(app, LABEL).await.map_err(|e| e.to_string())?;
        if keys.mac(LABEL).is_err() {
            keys.generate_mac(LABEL).map_err(|e| e.to_string())?;
        }
        lock.release().await.map_err(|e| e.to_string())?;
        keys.mac(LABEL).map_err(|e| e.to_string())
    };
    match made.await {
        Ok(mac) => Arc::new(KeyedPseudonyms(IpPseudonymKey::token(mac))),
        Err(error) => {
            tracing::warn!(%error, "address pseudonym key unavailable; no address is kept");
            Arc::new(NoPseudonyms)
        }
    }
}

/// The sources, and the MMDB file to watch when one is configured.
///
/// # Errors
/// An invalid range API base.
pub(crate) async fn services(
    config: &Config,
    app: &Pool,
    keys: &KeyStore,
    outbound: Outbound,
) -> Result<(RiskServices, Option<Arc<MmdbGeo>>), String> {
    let mmdb = config
        .risk
        .geo_mmdb_path
        .clone()
        .map(|p| Arc::new(MmdbGeo::open(p)));
    let geo: Arc<dyn access_identity_risk::ports::GeoResolver> = if let Some(m) = &mmdb {
        m.clone()
    } else {
        tracing::warn!(
            event = "geo.source.unavailable",
            "GeoIP source not configured; geographic signals are unavailable"
        );
        Arc::new(NoGeoSource)
    };
    let breach: Arc<dyn access_identity_risk::ports::BreachProbe> = match (
        &config.risk.breach_range_api,
        &config.risk.breach_ranges_dir,
    ) {
        (Some(base), _) => Arc::new(RangeProbe(
            RangeApi::new(base, OutboundFetch(outbound)).map_err(|e| e.to_string())?,
        )),
        (None, Some(dir)) => Arc::new(RangeProbe(MirrorRanges::new(dir.clone()))),
        (None, None) => Arc::new(NoBreachSource),
    };
    Ok((
        RiskServices {
            geo,
            ips: pseudonyms(app, keys).await,
            breach,
        },
        mmdb,
    ))
}

/// One refresh of the breach-range mirror at `root` from `source` (OP-156 m.3 (h)): a staged
/// version is downloaded, then made current and recorded in one step, the replaced one archived;
/// a refresh that stops is recorded as failed and the current version stays served. Under the
/// cell lock of the mirror, so one node refreshes a shared directory at a time.
///
/// # Errors
/// The store; a download failure is recorded, not returned.
pub(crate) async fn refresh_mirror<F: RangeFetch>(
    app: &Pool,
    root: &Path,
    source: &RangeApi<F>,
    source_host: &str,
    prefixes: impl Iterator<Item = String>,
) -> Result<Option<u32>, String> {
    use access_identity_risk::adapters::mirror::{download, promote};
    use access_store::payment::{
        fail_mirror_version, promote_mirror_version, stage_mirror_version,
    };
    let directory = root.to_string_lossy().into_owned();
    let lock = cell_lock(app, &format!("hibp-mirror:{directory}"))
        .await
        .map_err(|e| e.to_string())?;
    let id = stage_mirror_version(app, &directory, source_host)
        .await
        .map_err(|e| e.to_string())?;
    let done = match download(source, root, &id, prefixes).await {
        Ok(d) => promote(root, &id).await.map(|()| d),
        Err(e) => Err(e),
    };
    let out = match done {
        Ok(d) => {
            promote_mirror_version(app, id, d.ranges, &d.digest)
                .await
                .map_err(|e| e.to_string())?;
            tracing::info!(
                event = "hibp.mirror.refreshed",
                ranges = d.ranges,
                "breach-range mirror refreshed"
            );
            Some(d.ranges)
        }
        Err(e) => {
            fail_mirror_version(app, id)
                .await
                .map_err(|e| e.to_string())?;
            tracing::error!(
                event = "hibp.mirror.refresh_failed",
                reason = e.reason(),
                "breach-range mirror refresh failed; the current version stays"
            );
            None
        }
    };
    lock.release().await.map_err(|e| e.to_string())?;
    Ok(out)
}

/// Refreshes the mirror now and then every 24 hours, when the operator named a source.
pub(crate) fn mirror_refresh(
    config: &Config,
    app: Pool,
    outbound: Outbound,
) -> Option<tokio::task::JoinHandle<()>> {
    let root = config.risk.breach_ranges_dir.clone()?;
    let base = config.risk.breach_mirror_source.clone()?;
    let host = base
        .strip_prefix("https://")
        .and_then(|r| r.split(['/', ':']).next())
        .unwrap_or_default()
        .to_owned();
    let source = RangeApi::new(&base, OutboundFetch(outbound)).ok()?;
    Some(tokio::spawn(async move {
        let mut every =
            tokio::time::interval(access_identity_risk::adapters::mirror::REFRESH_EVERY);
        loop {
            every.tick().await;
            if let Err(error) = refresh_mirror(
                &app,
                &root,
                &source,
                &host,
                access_identity_risk::adapters::mirror::all_prefixes(),
            )
            .await
            {
                let _ = error;
                tracing::error!(
                    event = "hibp.mirror.refresh_failed",
                    reason = "store",
                    "breach-range mirror refresh failed; the current version stays"
                );
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::unused_async_trait_impl,
        reason = "test code"
    )]

    use std::sync::atomic::{AtomicBool, Ordering};

    use access_identity_account::adapters::hibp::MirrorRanges;
    use access_identity_account::ports::BreachRanges as _;

    use super::*;

    const SUFFIX: &str = "0018A45C4D1DEF81644B54AB7F969B88D65";

    /// A range source: each prefix lists one suffix with the count `generation`, padded with a
    /// zero-count line; `broken` fails `00002`.
    struct Source {
        generation: std::sync::atomic::AtomicU64,
        broken: AtomicBool,
        padded: AtomicBool,
    }

    impl RangeFetch for &Source {
        async fn get(
            &self,
            url: &str,
            headers: &[(&str, &str)],
            _: usize,
        ) -> Result<Fetched, NoAnswer> {
            if headers.contains(&access_identity_risk::adapters::range_api::ADD_PADDING) {
                self.padded.store(true, Ordering::SeqCst);
            }
            if self.broken.load(Ordering::SeqCst) && url.ends_with("/range/00002") {
                return Ok(Fetched {
                    status: 503,
                    body: Vec::new(),
                });
            }
            let n = self.generation.load(Ordering::SeqCst);
            Ok(Fetched {
                status: 200,
                body: format!("{SUFFIX}:{n}\r\n2DC183F740EE76F27B78EB39C8AD972A757:0\r\n")
                    .into_bytes(),
            })
        }
    }

    fn three() -> impl Iterator<Item = String> {
        ["00001", "00002", "00003"].into_iter().map(String::from)
    }

    // IDP-3, OP-156 m.3 (h), OP-73, Ek B 5396
    #[tokio::test]
    async fn a_refresh_that_stops_halfway_keeps_the_old_version_served() {
        let db = access_store::testing::fresh().await.unwrap();
        let root = std::env::temp_dir().join(format!("access-q6-mirror-{}", std::process::id()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let source = Source {
            generation: std::sync::atomic::AtomicU64::new(1),
            broken: AtomicBool::new(false),
            padded: AtomicBool::new(false),
        };
        let api = RangeApi::new("https://ranges.test", &source).unwrap();
        let mirror = MirrorRanges::new(root.clone());
        assert!(mirror.range("00001").await.is_err());

        let first = refresh_mirror(&db.app, &root, &api, "ranges.test", three())
            .await
            .unwrap();
        assert_eq!(first, Some(3));
        assert!(source.padded.load(Ordering::SeqCst));
        assert_eq!(
            mirror.range("00001").await.unwrap(),
            format!("{SUFFIX}:1\r\n")
        );

        source.generation.store(2, Ordering::SeqCst);
        source.broken.store(true, Ordering::SeqCst);
        let stopped = refresh_mirror(&db.app, &root, &api, "ranges.test", three())
            .await
            .unwrap();
        assert_eq!(stopped, None);
        assert_eq!(
            mirror.range("00001").await.unwrap(),
            format!("{SUFFIX}:1\r\n")
        );

        source.broken.store(false, Ordering::SeqCst);
        assert_eq!(
            refresh_mirror(&db.app, &root, &api, "ranges.test", three())
                .await
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            mirror.range("00003").await.unwrap(),
            format!("{SUFFIX}:2\r\n")
        );
        let versions = access_store::payment::mirror_versions(&db.app, &root.to_string_lossy())
            .await
            .unwrap();
        let status: Vec<&str> = versions.iter().map(|v| v.status.as_str()).collect();
        assert_eq!(status, ["current", "failed", "archived"]);
        let archived = access_identity_risk::adapters::mirror::version_dir(&root, &versions[2].id);
        assert!(
            tokio::fs::metadata(archived.join("00001.txt"))
                .await
                .is_ok()
        );
    }
}
