//! The domains as Claim Ingest's ledger (CMP-8, OP-150 m.6 (f)): each submission is recorded on
//! its domain's leader, a held Claim is indexed by its record and an issuer that used up its
//! quota is noted once per window (G44, §16.7).

use access_authority_ingest::ports::Ledger;
use access_authority_sequencer::ports::Clock;
use access_internal_api::claims::{ClaimSubmission, ClaimVerdict, Quarantine};
use access_internal_api::idp::Unavailable;
use access_kernel::claim;
use access_store::claims::{self as table, QuarantineRow};
use access_store::scope::DomainId;

use crate::CoreError;
use crate::adapters::Domains;
use crate::app::Ingested;
use crate::ports::{Binding, Keys, Salts};

fn unavailable(e: &CoreError) -> Unavailable {
    Unavailable(format!("claim-ingest: {e}"))
}

fn reason(word: &str) -> Option<Quarantine> {
    [
        Quarantine::SourceNotAccepted,
        Quarantine::Future,
        Quarantine::Quota,
    ]
    .into_iter()
    .find(|q| q.word() == word)
}

impl<K, B, S, C> Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    /// A resubmission held earlier answers with its last quarantine record (§9.13 rule 3).
    async fn held_before(&self, sub: &ClaimSubmission) -> Result<Option<ClaimVerdict>, CoreError> {
        let id = claim::claim_id(&sub.claim);
        let rows =
            table::quarantined(&self.setup.app, &DomainId::from_bytes(sub.domain.0), &id.0).await?;
        Ok(rows.last().and_then(|r| {
            Some(ClaimVerdict::Quarantined {
                claim: id,
                position: r.pos,
                reason: reason(&r.reason)?,
            })
        }))
    }

    /// Ingests `sub` on its domain's leader (CMP-8).
    ///
    /// # Errors
    /// [`CoreError`].
    pub async fn ingest(&self, sub: &ClaimSubmission) -> Result<Ingested, CoreError> {
        let mut guard = self.leading(sub.domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let mut result = led.core.ingest(sub, now).await;
        // §9.9.3 k.6, P50: the holders an admitted compromise declaration ended lose their
        // live families at its record, under the same leader
        if let Ok(done) = &result
            && let (ClaimVerdict::Admitted { position, .. }, false) =
                (&done.verdict, done.ended.is_empty())
        {
            let pos = *position;
            for holder in &done.ended {
                if let Err(e) = crate::status::adapters::revoke_holder(
                    &self.setup.sequencer,
                    sub.domain,
                    &holder.0,
                    pos,
                )
                .await
                {
                    result = Err(e);
                    break;
                }
            }
        }
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            *guard = None;
        }
        result
    }

    async fn index(&self, sub: &ClaimSubmission, done: &Ingested) -> Result<(), CoreError> {
        let domain = DomainId::from_bytes(sub.domain.0);
        let ClaimVerdict::Quarantined {
            claim,
            position,
            reason,
        } = done.verdict.clone()
        else {
            return Ok(());
        };
        // L2-CLM-3: kept by record, never dropped
        let row = QuarantineRow {
            pos: position,
            claim: claim.0,
            issuer: done.issuer.0,
            class: done.class.clone(),
            reason: String::from(reason.word()),
        };
        table::insert_quarantine(&self.setup.sequencer, &domain, &row).await?;
        // G44, §16.7
        if let Some((start, window_ms)) = done.quota {
            let window_s = u32::try_from(window_ms / 1_000).unwrap_or(u32::MAX);
            if table::quota_reached(
                &self.setup.sequencer,
                &domain,
                &done.issuer.0,
                start,
                window_s,
                position,
            )
            .await?
                && table::quota_notified(&self.setup.app, &domain, &done.issuer.0, start).await?
            {
                access_telemetry::counters::issuer_quota(u64::from(window_s));
            }
        }
        Ok(())
    }
}

impl<K, B, S, C> Ledger for Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn record(
        &self,
        submission: ClaimSubmission,
        resubmitted: bool,
    ) -> Result<ClaimVerdict, Unavailable> {
        if resubmitted
            && let Some(v) = self
                .held_before(&submission)
                .await
                .map_err(|e| unavailable(&e))?
        {
            return Ok(v);
        }
        let done = match self.ingest(&submission).await {
            Ok(done) => done,
            Err(CoreError::Protocol(code)) => {
                return Ok(ClaimVerdict::Rejected {
                    code: String::from(code),
                });
            }
            Err(e) => return Err(unavailable(&e)),
        };
        self.index(&submission, &done)
            .await
            .map_err(|e| unavailable(&e))?;
        Ok(done.verdict)
    }
}
