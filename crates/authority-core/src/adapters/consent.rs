//! A Grant as the identity plane's consent record reads it (§11.6 rule 1, P58, EI-18,
//! OP-154 m.3 (k)): its standing at the head, and the Party whose Instance signed the
//! `grant.issue` that created it.

use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::meta::{GrantContent, HoldingRef};
use access_kernel::model::Id;

use super::Domains;
use crate::CoreError;
use crate::ports::{Binding, Keys, Salts};

/// The Grant an allowed `grant.issue` Exercise created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuedGrant {
    /// The Grant.
    pub grant: Id,
    /// The Party that holds it.
    pub holder: Id,
    /// The Party whose Instance signed the Exercise.
    pub signer: Id,
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// Whether Grant `grant` of `domain` stands now, its lineage included (INV-5).
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader or trusted time.
    pub async fn grant_live(&self, domain: Digest, grant: Id) -> Result<bool, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        Ok(led
            .core
            .grant_facts(&grant, now)
            .await?
            .is_some_and(|g| g.live))
    }

    /// The live Grant held by one Party that the allowed Exercise `exercise` of `domain`
    /// created, with the Party whose Instance signed it (EI-18); `None` for an Exercise never
    /// allowed, one that created no Grant, a Grant that no longer stands, or one not held by one
    /// Party.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader or trusted time.
    pub async fn issued_grant(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> Result<Option<IssuedGrant>, CoreError> {
        let Some(record) = self.exercise_record(domain, exercise).await? else {
            return Ok(None);
        };
        let Some(instance) = record.instance else {
            return Ok(None);
        };
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        let Some(facts) = led.core.issued_by(&exercise, now).await? else {
            return Ok(None);
        };
        let (true, Some(holder)) = (facts.live, facts.holder) else {
            return Ok(None);
        };
        let Some(signer) = led.core.party_of_instance(&instance).await? else {
            return Ok(None);
        };
        Ok(Some(IssuedGrant {
            grant: facts.grant,
            holder,
            signer,
        }))
    }

    /// The Grant `party` would issue to itself for a consent in `domain` now, and the holding it
    /// comes from (§11.6, EI-18); `None` when it holds nothing it may pass on.
    ///
    /// # Errors
    /// [`CoreError`]; [`CoreError::Unavailable`] without the domain's leader or trusted time.
    pub async fn consent_basis(
        &self,
        domain: Digest,
        party: Id,
    ) -> Result<Option<(HoldingRef, GrantContent)>, CoreError> {
        let (guard, now) = self.led_now(domain).await?;
        let led = guard.as_ref().ok_or(CoreError::Unavailable("leader"))?;
        led.core.consent_basis(&party, now).await
    }
}
