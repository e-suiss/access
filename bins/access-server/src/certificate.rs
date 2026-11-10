//! Certificate, PIV and CAC sign-in of this process (OP-155 m.3 (m), §10.2.5): revocation
//! documents fetched through the SSRF-guarded outbound client, and the route over the hosted
//! login.

use std::sync::Arc;

use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_x509::app::Revocation;
use access_identity_x509::domain::{crl, ocsp};
use access_identity_x509::ports::{CaTrust, Fetch, Fetched, Request, Unreachable};

/// The guarded outbound client as the revocation fetcher: an OCSP `POST` or a CRL `GET`, a
/// `200` answer only, bounded by the document's own ceiling.
pub(crate) struct OutboundRevocation(pub(crate) Outbound);

impl Fetch for OutboundRevocation {
    fn fetch<'a>(&'a self, request: Request<'a>) -> Fetched<'a> {
        Box::pin(async move {
            let answer = match request {
                Request::Ocsp { url, body } => {
                    self.0
                        .revocation(
                            url,
                            Some((ocsp::REQUEST_TYPE, body)),
                            ocsp::RESPONSE_TYPE,
                            ocsp::MAX_RESPONSE,
                        )
                        .await
                }
                Request::Crl { url } => {
                    self.0
                        .revocation(url, None, crl::CRL_TYPE, crl::MAX_CRL)
                        .await
                }
            };
            match answer {
                Ok(a) if a.status == 200 => Ok(a.body),
                Ok(_) | Err(_) => {
                    tracing::info!(
                        event = "login.certificate.fetch",
                        outcome = "unreachable",
                        "revocation document not fetched"
                    );
                    Err(Unreachable)
                }
            }
        })
    }
}

/// What certificate sign-in needs: revocation over `outbound`, and the authority plane's CA
/// Acceptances.
pub(crate) fn certificates(
    outbound: Outbound,
    trust: Arc<dyn CaTrust>,
) -> access_identity_ui::app::certificate::Certificates {
    access_identity_ui::app::certificate::Certificates {
        revocation: Arc::new(Revocation::new(Arc::new(OutboundRevocation(outbound)))),
        trust,
    }
}

/// What SASL EXTERNAL on the LDAP gateway needs (OP-155 m.3 (n)): the same revocation and CA
/// Acceptances as certificate sign-in.
pub(crate) fn edge_certificates(
    outbound: Outbound,
    trust: Arc<dyn CaTrust>,
) -> access_identity_edge::app::ldap::Certificates {
    access_identity_edge::app::ldap::Certificates {
        revocation: Arc::new(Revocation::new(Arc::new(OutboundRevocation(outbound)))),
        trust,
    }
}
