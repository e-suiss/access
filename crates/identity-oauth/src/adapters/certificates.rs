//! The realm's client certificate checks over `identity-x509` (RFC 8705 §2.1, MD-8, OP-155
//! m.3 (k), (m)): the chain must lead to one of the CAs the realm named in its certificate
//! setting (`idp.realm.certificate_login`), the governing domain must hold an actor-binding
//! Acceptance of that CA, and every certificate of the path must be known not revoked (OCSP,
//! then CRL; unknown, unreachable or stale refuses). Only then are the leaf's names read.

use std::sync::Arc;

use access_identity_x509::app::{Refusal, Revocation};
use access_identity_x509::domain::cert::Cert;
use access_identity_x509::domain::login::ca_issuer;
use access_identity_x509::domain::path::verify;
use access_identity_x509::ports::CaTrust;
use access_store::Pool;
use access_store::identity::TenantTx;

use crate::domain::fapi::CertificateNames;
use crate::ports::oauth::Held;
use crate::ports::profile::{CertificateRefused, ClientCertificates};
use crate::ports::{RealmEntry, Unavailable};

/// Client certificates checked against the realm's CAs, their Acceptance and revocation.
pub struct X509ClientCertificates {
    app: Pool,
    revocation: Arc<Revocation>,
    trust: Arc<dyn CaTrust>,
}

impl X509ClientCertificates {
    /// Over the application pool, a revocation checker and the authority plane's CA
    /// Acceptances.
    #[must_use]
    pub fn new(app: Pool, revocation: Arc<Revocation>, trust: Arc<dyn CaTrust>) -> Self {
        Self {
            app,
            revocation,
            trust,
        }
    }

    async fn anchors(
        &self,
        realm: &RealmEntry,
    ) -> Result<Option<(Vec<Vec<u8>>, [u8; 32])>, Unavailable> {
        let down = |_| Unavailable;
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(down)?;
        let row = t.certificate_login().await.map_err(down)?;
        let domain = access_store::idp::governance(&mut t)
            .await
            .map_err(down)?
            .map(|g| *g.domain.as_bytes());
        t.commit().await.map_err(down)?;
        Ok(row
            .filter(|r| !r.anchors.is_empty())
            .zip(domain)
            .map(|(r, d)| (r.anchors, d)))
    }
}

fn names(leaf: &[u8]) -> Option<CertificateNames> {
    let c = Cert::parse(leaf).ok()?;
    let own = |v: Vec<&str>| v.into_iter().map(String::from).collect();
    Some(CertificateNames {
        subject_dn: c.subject_dn().unwrap_or_default(),
        dns: own(c.san_dns().ok()?),
        uri: own(c.san_uris().ok()?),
        ip: c.san_ips().ok()?,
        email: own(c.san_emails().ok()?),
    })
}

impl ClientCertificates for X509ClientCertificates {
    fn verify<'a>(
        &'a self,
        realm: &'a RealmEntry,
        chain: &'a [Vec<u8>],
        now_ms: u64,
    ) -> Held<'a, Result<CertificateNames, CertificateRefused>> {
        Box::pin(async move {
            let now = now_ms / 1000;
            let Some((anchors, domain)) = self.anchors(realm).await? else {
                return Ok(Err(CertificateRefused::Untrusted));
            };
            let Ok(path) = verify(chain, &anchors, now) else {
                return Ok(Err(CertificateRefused::Untrusted));
            };
            let Some(Ok(issuer)) = anchors.get(path.anchor).map(|a| ca_issuer(a)) else {
                return Ok(Err(CertificateRefused::Untrusted));
            };
            // §10.2.5, OP-155 m.3 (m)
            if !self
                .trust
                .accepted(domain, issuer)
                .await
                .map_err(|_| Unavailable)?
            {
                return Ok(Err(CertificateRefused::Untrusted));
            }
            // MD-8
            match self.revocation.check(&path, &anchors, now).await {
                Ok(()) => {}
                Err(Refusal::Revoked) => return Ok(Err(CertificateRefused::Revoked)),
                Err(Refusal::Unknown) => return Ok(Err(CertificateRefused::Unknown)),
            }
            Ok(names(path.leaf()).ok_or(CertificateRefused::Untrusted))
        })
    }
}
