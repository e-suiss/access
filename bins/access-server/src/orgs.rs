//! Organization domains outside the request path (TN-90, OP-153 m.3 (o)): the DNS-over-HTTPS,
//! HTTPS and RDAP probe a domain verification reads, and the watch that runs over every live
//! realm through the jobs table, one node per ten-minute slot (OP-129 m.2); the same pass ends
//! the guardianships of wards who reached majority (E53). Without a
//! configured resolver or RDAP service the probe answers nothing and no domain is verified or
//! lapsed by it (TI-9).

use std::time::Duration;

use access_identity_admin::app::domains::{DomainWatch, WatchPass};
use access_identity_admin::domain::dns::{self, Rtype};
use access_identity_admin::ports::DomainProbe;
use access_identity_oauth::adapters::outbound::Outbound;
use access_internal_api::idp::Unavailable;
use access_kernel::json::b64url_encode;
use access_store::Pool;
use access_store::StoreError;
use access_store::jobs::{claim_kind, complete, schedule};
use access_store::tenancy::routes;

/// The watch's job kind.
pub(crate) const DOMAINS: &str = "org-domains";

/// How often a node schedules and claims a watch pass (PD).
pub(crate) const INTERVAL: Duration = Duration::from_mins(10);

const LEASE: Duration = Duration::from_mins(15);

/// Largest DNS answer read (RFC 8484 over HTTPS).
const MAX_DNS: usize = 16 * 1024;

/// Largest RDAP document or challenge document read.
const MAX_DOC: usize = 64 * 1024;

/// The probe over the operator's DNS-over-HTTPS resolver and RDAP service.
#[derive(Clone)]
pub(crate) struct WebProbe {
    pub(crate) outbound: Outbound,
    /// `https://…/dns-query`.
    pub(crate) doh: Option<String>,
    /// `https://…/domain/`, the domain appended.
    pub(crate) rdap: Option<String>,
}

fn down(what: &str) -> Unavailable {
    Unavailable(format!("domain-probe: {what}"))
}

impl WebProbe {
    async fn records(&self, name: &str, rtype: Rtype) -> Result<Vec<String>, Unavailable> {
        let base = self.doh.as_deref().ok_or_else(|| down("no resolver"))?;
        let q = dns::query(name, rtype).map_err(|_| down("name"))?;
        let url = format!("{base}?dns={}", b64url_encode(&q));
        let a = self
            .outbound
            .get(&url, "application/dns-message", MAX_DNS)
            .await
            .map_err(|_| down("resolver"))?;
        if a.status != 200 {
            return Err(down("resolver status"));
        }
        dns::answers(&a.body, rtype).map_err(|_| down("answer"))
    }
}

/// The registrar an RDAP domain object names: the handle or public id of its `registrar`
/// entity (RFC 9083 §5.3).
fn registrar_of(doc: &serde_json::Value) -> Option<String> {
    doc.get("entities")?
        .as_array()?
        .iter()
        .find(|e| {
            e.get("roles")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|r| r.iter().any(|x| x.as_str() == Some("registrar")))
        })
        .and_then(|e| {
            e.get("publicIds")
                .and_then(|p| p.get(0))
                .and_then(|p| p.get("identifier"))
                .or_else(|| e.get("handle"))
                .and_then(serde_json::Value::as_str)
                .map(String::from)
        })
}

impl DomainProbe for WebProbe {
    async fn txt(&self, name: &str) -> Result<Vec<String>, Unavailable> {
        self.records(name, Rtype::Txt).await
    }

    async fn mx(&self, domain: &str) -> Result<Vec<String>, Unavailable> {
        self.records(domain, Rtype::Mx).await
    }

    async fn https(&self, url: &str) -> Result<Option<String>, Unavailable> {
        let a = self
            .outbound
            .get(url, "text/plain", MAX_DOC)
            .await
            .map_err(|e| {
                if e.transient() {
                    down("https")
                } else {
                    down("https url")
                }
            })?;
        Ok((a.status == 200).then(|| String::from_utf8_lossy(&a.body).into_owned()))
    }

    async fn registrar(&self, domain: &str) -> Result<Option<String>, Unavailable> {
        let base = self.rdap.as_deref().ok_or_else(|| down("no rdap"))?;
        let a = self
            .outbound
            .get(&format!("{base}{domain}"), "application/rdap+json", MAX_DOC)
            .await
            .map_err(|_| down("rdap"))?;
        match a.status {
            200 => {
                let doc: serde_json::Value =
                    serde_json::from_slice(&a.body).map_err(|_| down("rdap body"))?;
                Ok(registrar_of(&doc))
            }
            404 => Ok(None),
            _ => Err(down("rdap status")),
        }
    }

    fn idp_asserts(
        &self,
        _org: [u8; 16],
        _domain: &str,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send {
        // TN-90
        std::future::ready(Ok(false))
    }
}

/// Schedules this slot's watch pass and runs it over every live realm when this node claims it.
///
/// # Errors
/// [`StoreError`] when the jobs table or the realm list cannot be read.
pub(crate) async fn tick<P: DomainProbe>(
    (app, router): (&Pool, &Pool),
    probe: &P,
    worker: &str,
    now_ms: u64,
) -> Result<WatchPass, StoreError> {
    let slot = now_ms
        .checked_div(u64::try_from(INTERVAL.as_millis()).unwrap_or(600_000))
        .unwrap_or(0);
    schedule(
        app,
        DOMAINS,
        &slot.to_string(),
        &format!("{DOMAINS}:{slot}"),
        Duration::ZERO,
    )
    .await?;
    let mut out = WatchPass::default();
    let watch = DomainWatch { app, probe };
    for job in claim_kind(app, worker, DOMAINS, 2, LEASE).await? {
        let mut done = true;
        for route in routes(router).await? {
            // E53, OP-153 m.3 (q)
            if let Err(error) =
                access_identity_admin::app::household::majorities(app, (route.tenant, route.realm))
                    .await
            {
                done = false;
                tracing::warn!(%error, job = DOMAINS, "realm majority pass failed; retried");
            }
            match watch.realm((route.tenant, route.realm)).await {
                Ok(p) => {
                    out.verified = out.verified.saturating_add(p.verified);
                    out.changed = out.changed.saturating_add(p.changed);
                    out.lapsed = out.lapsed.saturating_add(p.lapsed);
                    out.contested = out.contested.saturating_add(p.contested);
                    out.unavailable = out.unavailable.saturating_add(p.unavailable);
                }
                Err(error) => {
                    done = false;
                    tracing::warn!(%error, job = DOMAINS, "realm domain watch failed; retried");
                }
            }
        }
        if done {
            complete(app, job.id, worker).await?;
        }
    }
    Ok(out)
}

/// Ticks the watch every [`INTERVAL`] until the task is aborted.
pub(crate) async fn run(app: Pool, router: Pool, probe: WebProbe, worker: String) {
    let mut every = tokio::time::interval(INTERVAL);
    loop {
        every.tick().await;
        let Some(now) = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
        else {
            continue;
        };
        if let Err(error) = tick((&app, &router), &probe, &worker, now).await {
            tracing::warn!(%error, job = DOMAINS, "domain watch not run");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // TN-90, RFC 9083 §5.3
    #[test]
    fn the_registrar_is_read_from_its_rdap_entity() {
        let doc = serde_json::json!({
            "entities": [
                { "roles": ["registrant"], "handle": "R-1" },
                { "roles": ["registrar"], "handle": "X", "publicIds": [{ "type": "IANA Registrar ID", "identifier": "1910" }] }
            ]
        });
        assert_eq!(registrar_of(&doc).as_deref(), Some("1910"));
        assert_eq!(registrar_of(&serde_json::json!({})), None);
    }
}
