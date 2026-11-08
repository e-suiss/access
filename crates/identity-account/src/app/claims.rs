//! The realm issuer at work (CMP-8, §10.1.7, OP-150 L2): identity events queue [`ClaimOrder`]s
//! in their own transaction, and the courier reads them from the identity outbox, places each in
//! the realm's governing domain, has the realm's Claim issuer key sign it and hands it to Claim
//! Ingest through `internal-api` (OP-62). The authority plane answers; it never writes back. An
//! order whose subject has no Party there yet, or whose realm has no issuer, is not a Claim.

use std::future::Future;

use access_internal_api::claims::{Carrier, ClaimIngest, ClaimSubmission, ClaimVerdict};
use access_internal_api::idp::Unavailable;
use access_kernel::claim;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_store::identity::{RealmId, TenantId, TenantTx, ack, cursor, poll};
use access_store::issuer::{self as store, IssuedClaim};
use access_store::{Pool, idp};

use crate::AccountError;
use crate::domain::claims::{Bind, ClaimOrder, OUTBOX_PREFIX, Placement};
use crate::ports::{AccountTx, Clock};

/// The courier's outbox cursor.
pub const CONSUMER: &str = "identity-claims";

/// Orders read per step.
pub const BATCH: u32 = 64;

/// Queues `order` in the caller's transaction (OP-10): it is issued only if the transaction
/// commits, and the event that caused it never waits for the authority plane.
///
/// # Errors
/// [`AccountError::Corrupt`] for an order that cannot be encoded; [`AccountError`].
pub async fn emit<T: AccountTx>(tx: &mut T, order: &ClaimOrder) -> Result<(), AccountError> {
    let bytes = order.to_bytes().map_err(|_| AccountError::Corrupt)?;
    tx.outbox(&order.kind(), &bytes).await
}

/// Signs a realm issuer's Claims with the realm's Claim issuer key (CMP-22b).
pub trait ClaimSigner: Send + Sync {
    /// The `COSE_Sign1` of the canonical statement `payload` signed at `at`.
    fn sign(
        &self,
        realm: RealmId,
        payload: Vec<u8>,
        at: u64,
    ) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send;
}

/// What became of one order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issued {
    /// Signed and answered by Claim Ingest.
    Answered {
        /// The `ClaimID`.
        claim: [u8; 16],
        /// The answer.
        verdict: ClaimVerdict,
    },
    /// Not a Claim: why, by stable word.
    Unplaced(&'static str),
}

/// What one courier step did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Orders answered by Claim Ingest.
    pub answered: u32,
    /// Orders that could not become Claims.
    pub unplaced: u32,
}

/// The realm issuer's courier.
pub struct Courier<S, I, C> {
    /// `access_app`, for the realm's rows.
    pub app: Pool,
    /// `access_outbox_reader`, for the outbox and the cursor.
    pub reader: Pool,
    /// The Claim issuer keys.
    pub signer: S,
    /// Claim Ingest of the authority plane.
    pub ingest: I,
    /// Time.
    pub clock: C,
}

fn down(e: impl std::fmt::Display) -> Unavailable {
    Unavailable(format!("claims: {e}"))
}

fn word(v: &ClaimVerdict) -> String {
    match v {
        ClaimVerdict::Admitted { .. } => String::from("admitted"),
        ClaimVerdict::Quarantined { reason, .. } => format!("quarantined-{}", reason.word()),
        ClaimVerdict::Rejected { code } => format!("rejected-{code}"),
    }
}

impl<S: ClaimSigner, I: ClaimIngest, C: Clock> Courier<S, I, C> {
    /// Where `order` lands in its realm, or why it does not.
    async fn place(
        &self,
        tenant: TenantId,
        realm: RealmId,
        order: &ClaimOrder,
    ) -> Result<Result<Placement, &'static str>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        let Some(issuer) = store::realm_issuer(&mut t).await.map_err(down)? else {
            return Ok(Err("no-issuer"));
        };
        let Some(g) = idp::governance(&mut t).await.map_err(down)? else {
            return Ok(Err("no-realm"));
        };
        let party = match order.party() {
            Some(p) => Some(p),
            None => idp::subject_party(&mut t, &order.subject)
                .await
                .map_err(down)?,
        };
        let Some(party) = party else {
            return Ok(Err("no-party"));
        };
        let instance = match order.bind {
            Bind::Session(s) => store::session_instance(&mut t, &s).await.map_err(down)?,
            _ => None,
        };
        let supersedes = match &order.line {
            Some(l) => store::last_in_line(&mut t, &order.subject, &g.domain, l)
                .await
                .map_err(down)?,
            None => None,
        };
        t.commit().await.map_err(down)?;
        Ok(Ok(Placement {
            domain: Digest(*g.domain.as_bytes()),
            issuer: Id(issuer),
            subject: Id(party),
            instance: instance.map(Id),
            supersedes: supersedes.map(Id),
            now: self.clock.now_ms(),
        }))
    }

    /// Issues `order` of `realm` now: places, signs, submits and records it. The synchronous
    /// path of an approval that needs its `authentication` Claim at once (§9.14.1) and the
    /// courier's step.
    ///
    /// # Errors
    /// [`Unavailable`] when the store, the signer or Claim Ingest cannot answer; the order can be
    /// issued again.
    pub async fn issue(
        &self,
        tenant: TenantId,
        realm: RealmId,
        order: &ClaimOrder,
    ) -> Result<Issued, Unavailable> {
        let p = match self.place(tenant, realm, order).await? {
            Ok(p) => p,
            Err(why) => return Ok(Issued::Unplaced(why)),
        };
        let Ok(prepared) = order.prepare(&p) else {
            return Ok(Issued::Unplaced("bad-order"));
        };
        let payload = prepared
            .statement
            .to_bytes()
            .map_err(|_| Unavailable(String::from("claims: encode")))?;
        let sign1 = self.signer.sign(realm, payload, p.now).await?;
        let id = claim::claim_id(&sign1);
        let verdict = self
            .ingest
            .ingest(ClaimSubmission {
                domain: p.domain,
                carrier: Carrier::Cose,
                claim: sign1,
                body: prepared.body,
                evidence: None,
            })
            .await?;
        let disposition = word(&verdict);
        let line = order.line.unwrap_or_else(|| {
            let mut l = [0; 32];
            l[..16].copy_from_slice(&id.0);
            l
        });
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        store::record_issued(
            &mut t,
            &IssuedClaim {
                subject: order.subject,
                class: &order.class,
                line,
                domain: access_store::scope::DomainId::from_bytes(p.domain.0),
                claim: id.0,
                disposition: &disposition,
            },
        )
        .await
        .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(Issued::Answered {
            claim: id.0,
            verdict,
        })
    }

    /// Issues the queued orders after the courier's cursor, at least once, and moves the cursor
    /// past each one it finished. An unreadable order is dropped with a warning; an outage stops
    /// the step where it is.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn step(&self) -> Result<Report, Unavailable> {
        let mut at = cursor(&self.reader, CONSUMER).await.map_err(down)?;
        let mut report = Report::default();
        for e in poll(&self.reader, at, BATCH).await.map_err(down)? {
            if e.kind.starts_with(OUTBOX_PREFIX) {
                let issued = match ClaimOrder::from_bytes(&e.payload) {
                    Ok(order) => self.issue(e.tenant, e.realm, &order).await?,
                    Err(_) => Issued::Unplaced("unreadable"),
                };
                if let Issued::Answered { verdict, .. } = &issued {
                    if let ClaimVerdict::Rejected { code } = verdict {
                        tracing::warn!(%code, kind = %e.kind, "claim rejected");
                    }
                    report.answered = report.answered.saturating_add(1);
                } else {
                    tracing::debug!(kind = %e.kind, ?issued, "claim order not placed");
                    report.unplaced = report.unplaced.saturating_add(1);
                }
            }
            at = access_store::identity::Cursor {
                xid: e.xid,
                id: e.id,
            };
            ack(&self.reader, CONSUMER, at).await.map_err(down)?;
        }
        Ok(report)
    }

    /// Steps every `every` until `stop` turns true.
    pub async fn run(&self, every: std::time::Duration, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        loop {
            if let Err(error) = self.step().await {
                tracing::warn!(error = %error.0, "claim courier step failed");
            }
            let _ = tokio::time::timeout(every, stop.changed()).await;
            if *stop.borrow() {
                return;
            }
        }
    }
}
