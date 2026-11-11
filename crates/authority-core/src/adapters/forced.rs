//! Forced recovery on a recovering install (§16.6 FR-2, FR-4, §13.6, OP-158 m.3 (m)): the
//! witness heads read from the witnesses themselves and recorded on this leader, and the
//! domain's declaration that it can be recovered.

use access_authority_sequencer::ports::Clock;
use access_authority_sequencer::witness::Target;
use access_authority_signer::adapters::call;
use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_kernel::verify::key_scope::{DomainMetadata, Recovery};

use crate::CoreError;
use crate::adapters::Domains;
use crate::app::forced::fetch_witness_heads;
use crate::ports::{Binding, Keys, Salts};

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    /// FR-2: reads each of `targets`' latest cosigned head of `domain` itself and records the
    /// ones that verify on this leader, ahead of the `domain_recover` decision; their Claim ids.
    /// A witness that gives none is left out, so the plan's quorum is incomplete.
    ///
    /// # Errors
    /// [`CoreError`] when this process cannot lead the domain or the commit gets no answer.
    pub async fn record_witness_heads(
        &self,
        domain: Digest,
        targets: &[Target],
    ) -> Result<Vec<Id>, CoreError> {
        let heads: Vec<_> = fetch_witness_heads(targets, &domain)
            .await
            .into_iter()
            .flatten()
            .collect();
        let (mut guard, now) = self.led_now(domain).await?;
        let led = guard.as_mut().ok_or(CoreError::Unavailable("leader"))?;
        led.core.record_witness_heads(&heads, now).await
    }
}

impl<K, B: Binding, S: Salts, C> Domains<K, B, S, C> {
    /// §13.6, OP-158 m.3 (m): publishes in the domain's metadata whether its Genesis carries a
    /// recovery entry; every other declaration stays as published.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the signer has no metadata or refuses.
    pub async fn declare_recovery(&self, domain: Digest, available: bool) -> Result<(), CoreError> {
        let path = self
            .setup
            .signer
            .as_deref()
            .ok_or(CoreError::Unavailable("signer"))?;
        if !super::open_keyring(path, domain).await {
            return Err(CoreError::Unavailable("signer-binding"));
        }
        let Ok(Ok(SignResponse::Metadata(signed))) = tokio::time::timeout(
            super::SIGNER_DEADLINE,
            call(path, &SignRequest::Metadata(domain)),
        )
        .await
        else {
            return Err(CoreError::Unavailable("metadata"));
        };
        let msg = access_kernel::verify::cose::parse_sign1(&signed)
            .map_err(|_| CoreError::Unavailable("metadata"))?;
        let m = DomainMetadata::from_bytes(msg.payload.as_deref().unwrap_or_default())
            .map_err(|_| CoreError::Unavailable("metadata"))?;
        let mut declared = m.declared;
        declared.recovery = Some(if available {
            Recovery::Available
        } else {
            Recovery::NotAvailable
        });
        let request = SignRequest::Declare {
            domain,
            declared: Box::new(declared),
        };
        match tokio::time::timeout(super::SIGNER_DEADLINE, call(path, &request)).await {
            Ok(Ok(SignResponse::Opened)) => Ok(()),
            _ => Err(CoreError::Unavailable("signer-binding")),
        }
    }
}
