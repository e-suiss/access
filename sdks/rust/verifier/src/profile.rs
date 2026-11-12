//! The verifier's own Verifier Profile (§9.12.1, L2-VPR-1, PI-12, U25): its digest, the
//! contracts it can honour, and the horizon ceiling it applies to each use (§9.10 step 2).

use access_kernel::claim::body::{Class, VerifierProfile, body_digest};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::tier::Tier;
use access_kernel::validity::{ProfileVariant, ValidityContract};
use access_kernel::verify::key_scope::{KeyScopeError, VerifierCaps};
use access_kernel::verify::pq::PqAnchor;
use access_kernel::verify::reanchor::PqBundle;

use crate::caps::{self, Ceiling, SECURE_CLOCK_CLASS};

/// The `checkpoint-continuation` parameter that carries the checkpoint interval.
pub const CHECKPOINT_PARAM: &str = "checkpoint_ms";

/// Why the verifier does not honour a contract. Each is a local DENY.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// The profile body cannot be encoded.
    #[error("profile-encoding")]
    Encoding,
    /// The contract was issued against another Verifier Profile.
    #[error("profile-reference")]
    Reference,
    /// The profile does not implement the variant or a parameter exceeds its ceiling.
    #[error("profile-coverage")]
    Coverage,
    /// The contract asks for another clock source class.
    #[error("profile-clock")]
    Clock,
    /// The variant needs an offline report the verifier does not send, or a tamper-evident
    /// counter it does not hold.
    #[error("profile-capability")]
    Capability,
    /// The policy default allows no projection of this variant at this tier.
    #[error("class-cap")]
    ClassCap,
    /// Δ or the checkpoint interval exceeds the class ceiling.
    #[error("class-cap-parameter")]
    Parameter,
    /// The tier needs a hardware-backed counter, a secure clock and attestation.
    #[error("class-cap-hardware")]
    Hardware,
    /// A CT2 offline extension is valid for one verifier only.
    #[error("class-cap-audience")]
    Audience,
}

impl ProfileError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Encoding => "profile-encoding",
            Self::Reference => "profile-reference",
            Self::Coverage => "profile-coverage",
            Self::Clock => "profile-clock",
            Self::Capability => "profile-capability",
            Self::ClassCap => "class-cap",
            Self::Parameter => "class-cap-parameter",
            Self::Hardware => "class-cap-hardware",
            Self::Audience => "class-cap-audience",
        }
    }
}

/// A Verifier Profile body and its digest, the `verifier_profile_ref` of the contracts issued
/// against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalProfile {
    body: VerifierProfile,
    digest: Digest,
    pq_anchors: alloc::vec::Vec<PqAnchor>,
}

impl LocalProfile {
    /// Computes the profile's digest (L2-CLB-1).
    ///
    /// # Errors
    /// [`ProfileError::Encoding`].
    pub fn new(body: VerifierProfile) -> Result<Self, ProfileError> {
        let digest = body_digest(Class::VerifierProfile, &body.to_value())
            .map_err(|_| ProfileError::Encoding)?;
        Ok(Self {
            body,
            digest: Digest(digest),
            pq_anchors: alloc::vec::Vec::new(),
        })
    }

    /// The profile with `anchors` pinned beforehand (`pq-anchor.cddl`, CR-45 RA-7, OP-159 m.3
    /// (h)): local to this verifier, never part of the body or its digest.
    #[must_use]
    pub fn with_pq_anchors(mut self, anchors: alloc::vec::Vec<PqAnchor>) -> Self {
        self.pq_anchors = anchors;
        self
    }

    /// The pinned post-quantum anchors.
    #[must_use]
    pub fn pq_anchors(&self) -> &[PqAnchor] {
        &self.pq_anchors
    }

    /// Accepts a classical artefact of `domain` with exact-content digest `artefact` after the
    /// classical algorithm's retirement only through `bundle` reaching an anchor this profile
    /// pinned (CR-45 RA-5, RA-7, L0-SIG-81).
    ///
    /// # Errors
    /// [`KeyScopeError::PqAnchorMissing`] without a pinned anchor for `domain`;
    /// [`KeyScopeError::Superseded`] without a bundle or when it does not reach the anchor.
    pub fn accept_retired(
        &self,
        backend: &impl suiss_crypto::sig::Backend,
        (domain, origin): (&Digest, &str),
        artefact: &Digest,
        bundle: Option<&PqBundle<'_>>,
    ) -> Result<(), KeyScopeError> {
        access_kernel::verify::reanchor::accept_retired(
            backend,
            &self.pq_anchors,
            (domain, origin),
            artefact,
            bundle,
        )
    }

    /// The body.
    #[must_use]
    pub const fn body(&self) -> &VerifierProfile {
        &self.body
    }

    /// The digest, the value of the `verifier_profile` Claim.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The canonical body bytes that travel beside the Claim.
    ///
    /// # Errors
    /// [`ProfileError::Encoding`].
    pub fn body_bytes(&self) -> Result<alloc::vec::Vec<u8>, ProfileError> {
        self.body.to_bytes().map_err(|_| ProfileError::Encoding)
    }

    /// The class ceiling for `contract` at `tier` (§13.7.2), with the CT2 offline extension
    /// only when Domain Metadata declares a CT2 ceiling.
    ///
    /// # Errors
    /// [`ProfileError::ClassCap`] or [`ProfileError::Audience`].
    pub fn ceiling(
        contract: &ValidityContract,
        tier: Tier,
        metadata: Option<&VerifierCaps>,
    ) -> Result<Ceiling, ProfileError> {
        if let Some(c) = caps::policy(contract.variant, tier) {
            return Ok(c);
        }
        // §13.7.2
        let extension = (contract.variant == ProfileVariant::CheckpointedOffline
            && tier == Tier::Ct2)
            .then(|| metadata?.horizon.get(&caps::ct(tier)).copied())
            .flatten()
            .ok_or(ProfileError::ClassCap)?;
        if contract.audience.len() != 1 {
            return Err(ProfileError::Audience);
        }
        Ok(caps::ct2_offline_extension(extension))
    }

    /// Whether the verifier honours `contract` for a use at `tier` (PI-12, §9.12.1, §13.7.2):
    /// the contract names this profile, the profile covers its variant and parameters, the
    /// clock class matches, the variant's duties are declared, and Δ and the checkpoint
    /// interval are within the class ceiling.
    ///
    /// # Errors
    /// [`ProfileError`].
    pub fn admits(
        &self,
        contract: &ValidityContract,
        tier: Tier,
        metadata: Option<&VerifierCaps>,
    ) -> Result<Ceiling, ProfileError> {
        // §9.12
        if contract.verifier_profile_ref != self.digest {
            return Err(ProfileError::Reference);
        }
        if !self.body.covers(contract.variant, &contract.params) {
            return Err(ProfileError::Coverage);
        }
        if contract.clock_source != self.body.clock_source {
            return Err(ProfileError::Clock);
        }
        let offline = contract.variant == ProfileVariant::CheckpointedOffline;
        let slices = !contract.offline_slice.is_empty();
        if (offline && !self.body.offline_report) || (slices && !self.body.tamper_evident_counter) {
            return Err(ProfileError::Capability);
        }
        let ceiling = Self::ceiling(contract, tier, metadata)?;
        if let (Some(cap), Some(delta)) = (ceiling.staleness_ms, contract.max_staleness_ms)
            && delta > cap
        {
            return Err(ProfileError::Parameter);
        }
        if let Some(cap) = ceiling.checkpoint_ms {
            let declared = contract.params.get(CHECKPOINT_PARAM).copied();
            if declared.is_none_or(|ms| ms > cap) {
                return Err(ProfileError::Parameter);
            }
        }
        if ceiling.hardware
            && !(self.body.tamper_evident_counter
                && self.body.attestation.is_some()
                && self.body.clock_source == SECURE_CLOCK_CLASS)
        {
            return Err(ProfileError::Hardware);
        }
        Ok(ceiling)
    }

    /// The effective horizon ceiling for a use (§9.10 step 2, OP-118 m.4): the smallest of the
    /// class ceiling, the profile's `cap_horizon` for the variant and tier, and the Domain
    /// Metadata ceiling for the tier. The artefact's own declaration is never used.
    #[must_use]
    pub fn horizon_cap(
        &self,
        ceiling: &Ceiling,
        variant: ProfileVariant,
        tier: Tier,
        metadata: Option<&VerifierCaps>,
    ) -> u64 {
        let ct = caps::ct(tier);
        [
            Some(ceiling.horizon_ms),
            self.body.cap_horizon(variant, ct),
            metadata.and_then(|m| m.horizon.get(&ct).copied()),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(0)
    }

    /// The clock skew for a use: the tier tolerance narrowed by the profile's (§13.7.2).
    #[must_use]
    pub fn skew_ms(&self, tier: Tier) -> u64 {
        caps::skew_ms(tier).min(self.body.clock_skew_ms)
    }
}
