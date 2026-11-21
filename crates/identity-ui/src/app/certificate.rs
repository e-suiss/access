//! Certificate, PIV and CAC sign-in on the hosted login (§10.2.5, MD-8, OP-155 m.3 (k), (m)).
//!
//! - Only a chain presented to the mTLS listener counts; it arrives from the TLS layer of
//!   access-server, never from a header.
//! - The chain must lead to a CA the environment names, and the governing domain must hold an
//!   actor-binding Acceptance of that CA; otherwise no Claim follows.
//! - Revocation fails closed: revoked, unknown, unreachable or stale refuses.
//! - The environment's rule maps exactly one subjectAltName entry to an active account. Every refusal
//!   answers the same, except a status that could not be checked.
//! - A certificate whose issuer policy the environment mapped as hardware-bound PIV signs in at AAL3;
//!   any other at most AAL2 and never CT3.

use std::sync::Arc;

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::domain::login::Problem;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_oauth::ports::EnvironmentEntry;
use access_identity_session::app::{FLOW_GONE, Step as Outcome};
use access_identity_session::domain::assurance::Factor;
use access_identity_session::ports::Clock;
use access_identity_x509::app::{Refusal, Revocation};
use access_identity_x509::domain::cert::Cert;
use access_identity_x509::domain::login::{
    Rule, ca_issuer, hardware_bound, identifier, thumbprint,
};
use access_identity_x509::domain::path::verify;
use access_identity_x509::ports::CaTrust;
use access_store::identity::TenantTx;

use super::{Body, Browser, Hosted, Reply, failed, signin};
use crate::ports::{EnvironmentKit, Kits, Messages};

/// What certificate sign-in needs beyond the login's services.
pub struct Certificates {
    /// Revocation, with its kept answers.
    pub revocation: Arc<Revocation>,
    /// The governing domain's CA Acceptances.
    pub trust: Arc<dyn CaTrust>,
}

impl core::fmt::Debug for Certificates {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Certificates").finish_non_exhaustive()
    }
}

/// The environment has not turned certificate sign-in on.
const CERTIFICATE_OFF: Problem = Problem {
    status: 404,
    code: "no-such-provider",
    title: "That sign-in option isn't available here",
    retry_after_s: None,
};

/// Why the sign-in page is shown again: the `certificate` query value it says (TN-172).
#[derive(Clone, Copy, Debug)]
enum Back {
    /// No certificate came, or the person closed the browser's picker.
    None,
    /// One answer for every refused certificate (`certificate.refused`).
    Refused,
    /// The certificate's revocation status could not be established (`certificate.status_unknown`,
    /// MD-8).
    StatusUnknown,
}

impl Back {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Refused => "refused",
            Self::StatusUnknown => "status_unknown",
        }
    }
}

/// A flow handle as the sign-in page puts it in its address.
fn handle(raw: &str) -> bool {
    (1..=64).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// TN-172: back to the sign-in page, on the flow it came from, saying why.
fn back(kit: &EnvironmentKit, flow: Option<&str>, why: Back) -> Reply {
    let to = match flow.filter(|f| handle(f)) {
        Some(f) => format!("{}/login?flow={f}&certificate={}", kit.issuer, why.as_str()),
        None => format!("{}/login?certificate={}", kit.issuer, why.as_str()),
    };
    Reply::new(303, Body::Redirect(to))
}

fn unavailable() -> Reply {
    Reply::problem(Problem {
        status: 503,
        code: "unavailable",
        title: "Temporarily unavailable",
        retry_after_s: Some(1),
    })
}

fn refused(why: &'static str) -> Back {
    tracing::info!(
        event = "login.certificate.refused",
        outcome = "refused",
        reason = why,
        "certificate refused"
    );
    Back::Refused
}

/// The environment's setting and its governing domain.
struct Setting {
    rule: Rule,
    anchors: Vec<Vec<u8>>,
    piv_policies: Vec<String>,
    domain: [u8; 32],
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn certificate_setting(&self, kit: &EnvironmentKit) -> Result<Option<Setting>, Reply> {
        let read = async {
            let mut t = TenantTx::begin(&self.db, kit.tenant, kit.environment).await?;
            let row = t.certificate_login().await?;
            let domain = access_store::idp::governance(&mut t)
                .await?
                .map(|g| *g.domain.as_bytes());
            t.commit().await?;
            Ok::<_, access_store::StoreError>((row, domain))
        };
        let (row, domain) = read.await.map_err(|_| unavailable())?;
        let (Some(row), Some(domain)) = (row.filter(|r| r.enabled), domain) else {
            return Ok(None);
        };
        let rule = Rule::parse(&row.rule).ok_or_else(unavailable)?;
        Ok(Some(Setting {
            rule,
            anchors: row.anchors,
            piv_policies: row.piv_policies,
            domain,
        }))
    }

    /// Whether the sign-in page offers a certificate: the environment turned it on and has a
    /// governing domain to accept its CAs (TN-172).
    pub(crate) async fn certificate_offered(&self, kit: &EnvironmentKit) -> bool {
        matches!(self.certificate_setting(kit).await, Ok(Some(_)))
    }

    async fn certificate_subject(
        &self,
        kit: &EnvironmentKit,
        id: &str,
        flow: Option<&str>,
    ) -> Result<[u8; 16], Reply> {
        let db = PgAccounts::sealed(self.db.clone(), kit.vault());
        let found = async {
            let mut tx = db.begin(kit.tenant, kit.environment).await?;
            let Some(subject) = tx.subject_by_identifier(id).await? else {
                return Ok(None);
            };
            let live = tx
                .subject(subject, false)
                .await?
                .and_then(|s| AccountStatus::parse(&s.status))
                .is_some_and(AccountStatus::can_authenticate);
            tx.commit().await?;
            Ok::<_, access_identity_account::AccountError>(live.then_some(subject))
        };
        match found.await {
            Ok(Some(s)) => Ok(s),
            Ok(None) => Err(back(kit, flow, refused("account"))),
            Err(_) => Err(unavailable()),
        }
    }

    /// `GET /login/certificate` on the mTLS listener: signs in with the client certificate
    /// `chain` (leaf first) the TLS layer handed over, then continues the flow or ends at the
    /// environment's landing page (§10.2.5, OP-155 m.3 (m)). A refusal goes back to the sign-in
    /// page on `flow`, the handle the page came from, and says why (TN-172).
    pub async fn certificate_login(
        &self,
        entry: &EnvironmentEntry,
        b: &Browser<'_>,
        flow: Option<&str>,
        chain: Option<&[Vec<u8>]>,
        certs: &Certificates,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let s = match self.certificate_setting(&kit).await {
            Ok(Some(s)) => s,
            Ok(None) => return Reply::problem(CERTIFICATE_OFF),
            Err(r) => return r,
        };
        // OP-155 m.3 (k)
        let Some(chain) = chain else {
            return back(&kit, flow, Back::None);
        };
        let now_ms = self.clock.now_ms();
        let now = now_ms / 1000;
        let Ok(path) = verify(chain, &s.anchors, now) else {
            return back(&kit, flow, refused("path"));
        };
        let Some(Ok(issuer)) = s.anchors.get(path.anchor).map(|a| ca_issuer(a)) else {
            return back(&kit, flow, refused("ca"));
        };
        // §10.2.5, OP-155 m.3 (m)
        match certs.trust.accepted(s.domain, issuer).await {
            Ok(true) => {}
            Ok(false) => return back(&kit, flow, refused("acceptance")),
            Err(_) => return unavailable(),
        }
        // MD-8
        match certs.revocation.check(&path, &s.anchors, now).await {
            Ok(()) => {}
            Err(Refusal::Revoked) => return back(&kit, flow, refused("revoked")),
            Err(Refusal::Unknown) => return back(&kit, flow, Back::StatusUnknown),
        }
        let Ok(leaf) = Cert::parse(path.leaf()) else {
            return back(&kit, flow, refused("malformed"));
        };
        let Ok(id) = identifier(&leaf, s.rule) else {
            return back(&kit, flow, refused("identifier"));
        };
        let subject = match self.certificate_subject(&kit, &id, flow).await {
            Ok(subject) => subject,
            Err(r) => return r,
        };
        let hardware = hardware_bound(&leaf, &s.piv_policies).unwrap_or(false);
        let factor = Factor::certificate(thumbprint(path.leaf()), hardware, now_ms);
        signin!(self, kit, auth, Some(b.ip));
        match auth
            .certificate(subject, factor, b.flow, b.correlation)
            .await
        {
            Ok(opened) => match opened.step {
                Outcome::SignedIn(signed) => Reply::new(303, Body::Redirect(self.done_to(&kit)))
                    .cookie(signed.set_cookie)
                    .cookie(signed.marker_cookie)
                    .cookie(opened.set_cookie),
                Outcome::Continue { .. } => Reply::new(
                    303,
                    Body::Redirect(format!("{}/login?flow={}", kit.issuer, opened.handle)),
                )
                .cookie(opened.set_cookie),
                _ => Reply::problem(FLOW_GONE),
            },
            Err(e) => failed(&e),
        }
    }
}
