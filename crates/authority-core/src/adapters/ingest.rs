//! The domains as Claim Ingest's ledger (CMP-8, OP-150 m.6 (f)): each submission is recorded on
//! its domain's leader, a held Claim is indexed by its record and an issuer that used up its
//! quota is noted once per window (G44, §16.7).

use access_authority_ingest::ports::Ledger;
use access_authority_sequencer::ports::Clock;
use access_internal_api::claims::{ClaimSubmission, ClaimVerdict, Quarantine};
use access_internal_api::idp::Unavailable;
use access_kernel::claim;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_store::claims::{self as table, QuarantineRow};
use access_store::offline::{ProfileRow, ReconciliationRow, insert_profile, reconciliations};
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

    /// The refusal of a Claim whose issuer is chain-constrained and whose chain does not hold
    /// at trusted time (IDI-12, OP-155 m.3 (j)); `None` lets it through to verification. The
    /// Acceptance is never read or written here.
    async fn chain_gate(&self, sub: &ClaimSubmission) -> Result<Option<ClaimVerdict>, CoreError> {
        use access_authority_ingest::chain::{self, Fact, Status};
        use access_store::oidf::ChainState;
        let named = chain::named(sub);
        if named.party.is_none() && named.entity.is_none() {
            return Ok(None);
        }
        let rows = access_store::oidf::issuer_states(
            &self.setup.app,
            &DomainId::from_bytes(sub.domain.0),
            named.entity.as_deref(),
            named.party.map(|p| p.0),
        )
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let now = {
            let mut guard = self.leading(sub.domain).await?;
            let Some(led) = guard.as_mut() else {
                return Err(CoreError::Unavailable("leader"));
            };
            led.clock
                .now()
                .await
                .map_err(|_| CoreError::Unavailable("time"))?
        };
        let facts: Vec<Fact> = rows
            .iter()
            .map(|r| Fact {
                status: match r.state {
                    ChainState::Pending => Status::Pending,
                    ChainState::Resolved => Status::Resolved,
                    ChainState::Unresolved => Status::Unresolved,
                    ChainState::Conflict => Status::Conflict,
                },
                checked_ms: r.checked_ms,
                chain_exp_ms: r.chain_exp_ms,
            })
            .collect();
        Ok(chain::gate(&facts, now)
            .err()
            .map(|r| ClaimVerdict::Rejected {
                code: String::from(r.0),
            }))
    }

    /// The issuers `domain` accepts for `actor-binding` whose pinned key set names `iss`, at
    /// the leader's trusted time (§11.11.3 step 1, AG-29, OP-154 m.3 (q)).
    ///
    /// # Errors
    /// [`CoreError`].
    pub async fn assertion_issuers(
        &self,
        domain: Digest,
        iss: &str,
    ) -> Result<Vec<(Id, claim::Pinned)>, CoreError> {
        let mut guard = self.leading(domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        led.core.assertion_issuers(iss, now).await
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
        // §9.9.3 k.6, P50
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
        // §9.12.1, §7.9.4.1
        if let Ok(done) = &result
            && let ClaimVerdict::Admitted {
                position,
                claim,
                replayed: false,
            } = &done.verdict
            && let Some(body) = &sub.body
        {
            let kept = match done.class.as_str() {
                "verifier_profile" => {
                    self.keep_profile(sub.domain, (*position, *claim), body, done.until)
                        .await
                }
                "offline_exercise_report" => super::reconcile::reconcile(
                    (&self.setup.sequencer, &self.setup.app),
                    sub.domain,
                    (*position, *claim),
                    body,
                    now,
                )
                .await
                .map(|_| ()),
                // EI-5, OP-156 m.3 (t)
                crate::app::commitment::CLASS => {
                    self.keep_termination(sub.domain, done, (*position, *claim), body)
                        .await
                }
                _ => Ok(()),
            };
            if let Err(e) = kept {
                result = Err(e);
            }
        }
        // OP-156 m.3 (k), INV-32
        if let Ok(done) = &result
            && let (
                ClaimVerdict::Admitted {
                    position, claim, ..
                },
                Some(l),
            ) = (&done.verdict, &done.lifecycle)
            && let Err(e) = access_store::resources::insert_incarnation(
                &self.setup.sequencer,
                &DomainId::from_bytes(sub.domain.0),
                &access_store::resources::IncarnationRow {
                    namespace: l.resource.namespace.clone(),
                    path: l.resource.path.clone(),
                    incarnation: l.resource.incarnation,
                    event: String::from(l.event.name()),
                    claim: claim.0,
                    issuer: done.issuer.0,
                    pos: *position,
                },
            )
            .await
        {
            result = Err(e.into());
        }
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            *guard = None;
        }
        result
    }

    /// Records an admitted `commitment_active` Claim whose disclosed body says the commitment
    /// ended, for the inventory (§8.17.7.2); a body that does not match the Claim's value, or an
    /// active one, records nothing.
    async fn keep_termination(
        &self,
        domain: Digest,
        done: &Ingested,
        (pos, claim): (u64, Id),
        body: &[u8],
    ) -> Result<(), CoreError> {
        let Some((commitment, false)) = crate::app::commitment::decode(done.value.as_ref(), body)
        else {
            return Ok(());
        };
        Ok(access_store::commitments::record_termination(
            &self.setup.sequencer,
            &DomainId::from_bytes(domain.0),
            &access_store::commitments::Termination {
                commitment: commitment.0,
                pos,
                claim: claim.0,
                issuer: done.issuer.0,
                subject: done.subject.0,
            },
        )
        .await?)
    }

    /// Keeps an admitted Verifier Profile body under the verifier it names, with the Claim's
    /// validity end (§9.12.1): what `projection.issue` reads the audience's profile from.
    async fn keep_profile(
        &self,
        domain: Digest,
        (pos, claim): (u64, Id),
        body: &[u8],
        until: u64,
    ) -> Result<(), CoreError> {
        use access_kernel::claim::body::{Body, Class, VerifierId, body_digest};
        use suiss_crypto::dcbor::{self, Limits};
        let value = dcbor::decode(body, Limits::CEILING)
            .map_err(|_| CoreError::Protocol("verifier-profile"))?;
        let Body::VerifierProfile(p) = Body::from_value(Class::VerifierProfile, &value)
            .map_err(|_| CoreError::Protocol("verifier-profile"))?
        else {
            return Err(CoreError::Protocol("verifier-profile"));
        };
        let verifier = match &p.verifier {
            VerifierId::Workload(w) => w.clone(),
            VerifierId::Instance(i) => access_kernel::json::b64url_encode(&i.0),
        };
        let digest = body_digest(Class::VerifierProfile, &value)
            .map_err(|_| CoreError::Protocol("verifier-profile"))?;
        Ok(insert_profile(
            &self.setup.sequencer,
            &DomainId::from_bytes(domain.0),
            &ProfileRow {
                pos,
                digest,
                claim: claim.0,
                body: body.to_vec(),
                verifier: Some(verifier),
                valid_until_ms: Some(until),
            },
        )
        .await?)
    }

    /// What the Offline Exercise Reports of the projection `exercise` came to, in record order
    /// (§7.9.4.1): the reconciliation view of the Exercise.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn reconciliation(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> Result<Vec<ReconciliationRow>, CoreError> {
        Ok(reconciliations(
            &self.setup.app,
            &DomainId::from_bytes(domain.0),
            &exercise.0,
        )
        .await?)
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
        // L2-CLM-3
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
        if let Some(v) = self
            .chain_gate(&submission)
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
