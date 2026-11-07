//! The SL2 risk sources of this process (TN-46, OP-151 m.1 (b), m.3 (o)): the MMDB GeoIP/ASN
//! file, the breach range API through the SSRF-guarded outbound client or a local mirror, and the
//! cell's address pseudonym key in the token. A source that is not configured answers
//! `unavailable` and the management surface states it.

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
    async fn get(&self, url: &str, max_body: usize) -> Result<Fetched, NoAnswer> {
        let a = self
            .0
            .get(url, "text/plain", max_body)
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
