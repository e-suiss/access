//! The sandbox line at the decision point (OP-151 m.3 (m), X21): a request brings no authority
//! across it. A foreign PAP it presents, or the foreign domain an Acceptance it establishes or
//! amends would open to, must be on the same side of the line as the domain it addresses; a
//! request that crosses is refused before it is evaluated, and when a side cannot be told the
//! request is unavailable (MD-8). There is no flag that lifts the line.

use std::future::Future;

use access_authority_core::CoreError;
use access_authority_core::app::{Incoming, Response, Scope};
use access_authority_core::domain::{ProofRef, Request};
use access_authority_core::query::Query;
use access_identity_admin::domain::provision::{Regime, flows};
use access_kernel::digest::Digest;
use access_kernel::foreign::claimed_domain;
use access_kernel::meta::Payload;
use access_kernel::model::Id;

use super::ports::{Page, Pdp};

/// The stable code of a request refused at the sandbox line.
pub const SANDBOX_LINE: &str = "sandbox-line";

/// Which side of the sandbox line a domain is on.
pub trait Regimes: Send + Sync {
    /// The regime of `domain`; an unknown domain is production.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when it cannot be told.
    fn regime(&self, domain: Digest) -> impl Future<Output = Result<Regime, CoreError>> + Send;
}

/// The other domains `req` would bring authority from: the domains of the foreign PAPs it
/// presents, and the foreign domain of an Acceptance it establishes or amends.
#[must_use]
pub fn foreign_domains(req: &Request) -> Vec<Digest> {
    let mut out: Vec<Digest> = req
        .proofs
        .iter()
        .filter_map(|p| match p {
            ProofRef::ForeignPap { pap, .. } => claimed_domain(pap),
            _ => None,
        })
        .collect();
    let content = match &req.payload {
        Some(Payload::AcceptanceEstablish(c) | Payload::AcceptanceAmend { content: c, .. }) => {
            Some(c)
        }
        _ => None,
    };
    if let Some(d) = content.and_then(named_domain) {
        out.push(d);
    }
    out.retain(|d| *d != req.domain);
    out.sort_unstable_by_key(|d| d.0);
    out.dedup();
    out
}

/// The foreign domain an Acceptance's content names as its issuer, decoded no further than that:
/// content that names one is checked even when the rest of it would not decode.
fn named_domain(content: &suiss_crypto::dcbor::Value) -> Option<Digest> {
    let suiss_crypto::dcbor::Value::Map(issuer) = content.get("issuer")? else {
        return None;
    };
    issuer.iter().find_map(|(k, v)| {
        (*k == suiss_crypto::dcbor::Value::text("foreign"))
            .then(|| v.get("domain").and_then(Digest::from_value))
            .flatten()
    })
}

/// A decision point behind the sandbox line.
pub struct SandboxLine<P, R> {
    /// The decision point.
    pub inner: P,
    /// Which side each domain is on.
    pub regimes: R,
}

impl<P: Pdp, R: Regimes> SandboxLine<P, R> {
    /// Refuses `inc` when it brings authority across the line (OP-151 m.3 (m)).
    async fn check(&self, inc: &Incoming) -> Result<(), CoreError> {
        let others = foreign_domains(&inc.request);
        if others.is_empty() {
            return Ok(());
        }
        let home = self.regimes.regime(inc.request.domain).await?;
        for d in others {
            if !flows(home, self.regimes.regime(d).await?) {
                tracing::warn!(
                    event = "adp.sandbox_line.refused",
                    outcome = "refused",
                    "a request would bring authority across the sandbox line"
                );
                return Err(CoreError::Protocol(SANDBOX_LINE));
            }
        }
        Ok(())
    }
}

impl<P: Pdp, R: Regimes> Pdp for SandboxLine<P, R> {
    async fn evaluate(&self, inc: Incoming) -> Result<Response, CoreError> {
        self.check(&inc).await?;
        self.inner.evaluate(inc).await
    }

    async fn explain_recorded(
        &self,
        inc: Incoming,
        record: u64,
        scope: Scope,
    ) -> Result<Response, CoreError> {
        self.inner.explain_recorded(inc, record, scope).await
    }

    async fn eligible(&self, inc: Incoming, subject: Id) -> Result<Response, CoreError> {
        self.check(&inc).await?;
        self.inner.eligible(inc, subject).await
    }

    async fn search(
        &self,
        inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> Result<Page, CoreError> {
        self.inner.search(inc, query, page).await
    }

    async fn metadata(&self, domain: Digest) -> Option<Vec<u8>> {
        self.inner.metadata(domain).await
    }

    async fn export(&self, inc: Incoming) -> Result<Vec<u8>, CoreError> {
        self.inner.export(inc).await
    }
}

#[cfg(test)]
mod tests;
