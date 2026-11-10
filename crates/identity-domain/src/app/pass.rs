//! The pass over a realm's custom domains (OP-156 m.3 (i)): it reads the records of each
//! registration that is due, moves it between pending, verified, lapsed and expired, and orders
//! a certificate for each verified one that has none or whose renewal is due. A domain whose
//! verification lapsed renews nothing and is not served. A DNS or ACME outage changes nothing.

use access_store::Pool;
use access_store::StoreError;
use access_store::custom_domains::{
    self as store, Checked, DomainRow, NewCertificate, active_certificates,
};
use access_store::identity::{RealmId, TenantId, TenantTx};

use crate::adapters::seal::{KeySeal, RealmKek};
use crate::app::acme::Client;
use crate::domain::host::CustomHost;
use crate::domain::schedule::{renew_after, retry_after};
use crate::domain::verify::{self, Registration, Status, Step};
use crate::ports::{AccountKey, AcmeHttp, Challenges, DnsProbe, Pause, Unavailable};

/// Who the pass's audit events name as actor.
pub const ACTOR: &str = "access-custom-domains";

async fn audit(t: &mut TenantTx, event: &str, host: &str) -> Result<(), StoreError> {
    let correlation = access_kernel::json::b64url_encode(
        &access_crypto::random::bytes::<16>().map_err(|_| StoreError::Range)?,
    );
    t.audit(&access_store::audit::AuditEvent {
        event_type: event,
        actor: ACTOR,
        target: host,
        correlation: &correlation,
    })
    .await
}

/// What one pass over a realm did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Registrations found verified (first time or again).
    pub verified: u32,
    /// Verifications that lapsed.
    pub lapsed: u32,
    /// Pending registrations that timed out.
    pub expired: u32,
    /// Certificates issued or renewed.
    pub issued: u32,
    /// Orders that failed.
    pub failed: u32,
    /// Checks or orders that could not run; nothing changed for them.
    pub unavailable: u32,
}

/// The ACME side of a pass; without it no certificate is ordered.
pub struct Acme<'a, H, K, P> {
    /// The client.
    pub client: Client<'a, H, K, P>,
}

/// One pass's dependencies.
pub struct Pass<'a, D, H, K, P, C, R> {
    /// The `access_app` pool.
    pub app: &'a Pool,
    /// DNS over the operator's resolver.
    pub dns: &'a D,
    /// ACME, when configured.
    pub acme: Option<Acme<'a, H, K, P>>,
    /// This node's TLS-ALPN-01 answers.
    pub challenges: &'a C,
    /// The realm KEKs.
    pub keys: &'a KeySeal<R>,
}

fn registration(d: &DomainRow) -> Option<Registration> {
    Some(Registration {
        host: CustomHost::stored(&d.hostname),
        status: Status::parse(&d.status)?,
        registered_at: d.registered_at,
        reverify_by: d.reverify_by,
        checked_at: d.checked_at,
    })
}

/// Publishes a challenge as an open order of the realm, so every node serves it, then on
/// this node at once.
struct Board<'a, C> {
    app: &'a Pool,
    scope: (TenantId, RealmId),
    domain: [u8; 16],
    local: &'a C,
}

fn down(e: impl core::fmt::Display) -> Unavailable {
    Unavailable(e.to_string())
}

impl<C: Challenges> Challenges for Board<'_, C> {
    async fn publish(&self, host: &str, digest: [u8; 32]) -> Result<(), Unavailable> {
        let order = access_crypto::random::bytes::<16>().map_err(down)?;
        let mut t = TenantTx::begin(self.app, self.scope.0, self.scope.1)
            .await
            .map_err(down)?;
        store::close_orders(&mut t, host, "failed", Some("acme-abandoned"))
            .await
            .map_err(down)?;
        store::open_order(&mut t, order, self.domain, host, &digest)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        self.local.publish(host, digest).await
    }

    async fn withdraw(&self, host: &str) -> Result<(), Unavailable> {
        self.local.withdraw(host).await
    }
}

impl<D, H, K, P, C, R> Pass<'_, D, H, K, P, C, R>
where
    D: DnsProbe,
    H: AcmeHttp,
    K: AccountKey,
    P: Pause,
    C: Challenges,
    R: RealmKek,
{
    async fn check(
        &self,
        scope: (TenantId, RealmId),
        d: &DomainRow,
        now_s: i64,
        out: &mut Outcome,
    ) -> Result<(), StoreError> {
        let Some(r) = registration(d) else {
            return Err(StoreError::Corrupt);
        };
        let (status, finding, by) = match verify::due(&r, now_s) {
            Step::Wait => return Ok(()),
            Step::Expire => (Status::Expired, "pending-expired", None),
            Step::Check => {
                let txt = self.dns.txt(&r.host.challenge_name()).await;
                let cname = self.dns.cname(r.host.as_str()).await;
                let (Ok(txt), Ok(cname)) = (txt, cname) else {
                    tracing::warn!(
                        event = "domain.recheck.failed",
                        plane = "ops",
                        "custom domain records not read; nothing changed"
                    );
                    out.unavailable = out.unavailable.saturating_add(1);
                    return Ok(());
                };
                let f = verify::finding(&d.challenge, &txt, &cname, &d.cname_target);
                let (status, by) = verify::after(&r, f, now_s);
                (status, f.code(), by)
            }
        };
        let mut t = TenantTx::begin(self.app, scope.0, scope.1).await?;
        let checked = Checked {
            id: d.id,
            status: status.name(),
            finding,
            reverify_by: by,
            now: now_s,
        };
        match store::record_check(&mut t, &checked).await {
            Ok(_) => {
                // OP-156 m.3 (i), OP-41
                match (r.status, status) {
                    (Status::Verified, Status::Verified) => {}
                    (_, Status::Verified) => audit(&mut t, "domain.verified", &d.hostname).await?,
                    (Status::Verified, Status::Lapsed) | (_, Status::Expired) => {
                        audit(&mut t, "domain.verification_failed", &d.hostname).await?;
                    }
                    _ => {}
                }
                t.commit().await?;
            }
            Err(e) if e.integrity() => {
                drop(t);
                let mut t = TenantTx::begin(self.app, scope.0, scope.1).await?;
                let held = Checked {
                    status: if r.status == Status::Pending {
                        Status::Pending.name()
                    } else {
                        Status::Lapsed.name()
                    },
                    finding: "held-by-another-realm",
                    reverify_by: r.reverify_by,
                    ..checked
                };
                store::record_check(&mut t, &held).await?;
                t.commit().await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        match (r.status, status) {
            (Status::Verified, Status::Verified) => {}
            (_, Status::Verified) => out.verified = out.verified.saturating_add(1),
            (Status::Verified, Status::Lapsed) => out.lapsed = out.lapsed.saturating_add(1),
            (_, Status::Expired) => out.expired = out.expired.saturating_add(1),
            _ => {}
        }
        Ok(())
    }

    async fn certify(
        &self,
        acme: &Acme<'_, H, K, P>,
        scope: (TenantId, RealmId),
        d: &DomainRow,
        now_s: i64,
        out: &mut Outcome,
    ) -> Result<(), StoreError> {
        let board = Board {
            app: self.app,
            scope,
            domain: d.id,
            local: self.challenges,
        };
        let issued = acme.client.issue(&d.hostname, now_s, &board).await;
        let mut t = TenantTx::begin(self.app, scope.0, scope.1).await?;
        match issued {
            Ok(issued) => {
                let id = access_crypto::random::bytes::<16>().map_err(|_| StoreError::Range)?;
                let Ok(key) =
                    self.keys
                        .seal(scope.0, scope.1, &id, issued.key_pkcs8.expose().as_slice())
                else {
                    out.unavailable = out.unavailable.saturating_add(1);
                    store::close_orders(&mut t, &d.hostname, "failed", Some("kek-unavailable"))
                        .await?;
                    t.commit().await?;
                    return Ok(());
                };
                store::put_certificate(
                    &mut t,
                    &NewCertificate {
                        id,
                        domain: d.id,
                        hostname: &d.hostname,
                        chain_pem: &issued.chain_pem,
                        key: &key,
                        not_before: issued.leaf.not_before,
                        not_after: issued.leaf.not_after,
                        renew_after: renew_after(issued.leaf.not_before, issued.leaf.not_after),
                    },
                )
                .await?;
                store::close_orders(&mut t, &d.hostname, "valid", None).await?;
                store::record_acme(&mut t, d.id, 0, None, None).await?;
                audit(&mut t, "acme.certificate_issued", &d.hostname).await?;
                out.issued = out.issued.saturating_add(1);
            }
            Err(e) => {
                let failures = d.acme_failures.saturating_add(1);
                store::close_orders(&mut t, &d.hostname, "failed", Some(e.code())).await?;
                store::record_acme(
                    &mut t,
                    d.id,
                    failures,
                    Some(now_s.saturating_add(retry_after(failures))),
                    Some(e.code()),
                )
                .await?;
                tracing::error!(
                    event = "acme.renewal.failed",
                    plane = "ops",
                    error = e.code(),
                    "custom domain certificate not issued"
                );
                audit(&mut t, "acme.order_failed", &d.hostname).await?;
                out.failed = out.failed.saturating_add(1);
            }
        }
        t.commit().await?;
        Ok(())
    }

    /// Runs the pass over realm `scope` at `now_s`.
    ///
    /// # Errors
    /// [`StoreError`] when the realm's rows cannot be read or written.
    pub async fn realm(
        &self,
        scope: (TenantId, RealmId),
        now_s: i64,
    ) -> Result<Outcome, StoreError> {
        let mut out = Outcome::default();
        let mut t = TenantTx::begin(self.app, scope.0, scope.1).await?;
        let domains = store::domains(&mut t).await?;
        t.commit().await?;
        for d in &domains {
            self.check(scope, d, now_s, &mut out).await?;
        }
        let Some(acme) = &self.acme else {
            return Ok(out);
        };
        let mut t = TenantTx::begin(self.app, scope.0, scope.1).await?;
        let domains = store::domains(&mut t).await?;
        let certs = active_certificates(&mut t).await?;
        t.commit().await?;
        for d in &domains {
            let Some(r) = registration(d) else { continue };
            // OP-156 m.3 (i)
            if !verify::served(&r, now_s) || d.acme_next_at.is_some_and(|n| now_s < n) {
                continue;
            }
            let current = certs.iter().find(|c| c.domain == d.id);
            if current.is_some_and(|c| now_s < c.renew_after) {
                continue;
            }
            self.certify(acme, scope, d, now_s, &mut out).await?;
        }
        Ok(out)
    }
}

/// A certificate the TLS listener serves: its host, chain (DER, leaf first) and PKCS#8 key.
pub struct Served {
    /// The host.
    pub host: String,
    /// The chain, DER, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The key, PKCS#8.
    pub key: zeroize::Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Served {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Served")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// The certificates of realm `scope`'s domains among `served` (the verified hosts whose
/// verification holds) that are still valid at `now_s`, their keys opened under the realm KEK.
/// A key that does not open is left out.
///
/// # Errors
/// [`StoreError`].
pub async fn served<R: RealmKek>(
    app: &Pool,
    keys: &KeySeal<R>,
    scope: (TenantId, RealmId),
    served: &[String],
    now_s: i64,
) -> Result<Vec<Served>, StoreError> {
    let mut t = TenantTx::begin(app, scope.0, scope.1).await?;
    let certs = active_certificates(&mut t).await?;
    t.commit().await?;
    let mut out = Vec::new();
    for c in certs {
        if !served.contains(&c.hostname) || c.not_after <= now_s {
            continue;
        }
        let Ok(chain) = crate::x509::pem_chain(&c.chain_pem, crate::app::acme::MAX_CHAIN) else {
            continue;
        };
        match keys.open(scope.0, scope.1, &c.id, &c.key) {
            Ok(key) => out.push(Served {
                host: c.hostname,
                chain,
                key,
            }),
            Err(error) => tracing::error!(%error, "custom domain certificate key did not open"),
        }
    }
    Ok(out)
}
