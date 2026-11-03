//! A realm's WebAuthn verification policy (§10.2.4).

use super::cose::CoseAlgorithm;
use super::ids::Aaguid;

/// `userVerification` (§10.2.4: default `preferred`; CT2+ and AAL2+ need UV = 1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UserVerification {
    /// UV = 1 is enforced.
    Required,
    /// Requested, not enforced.
    #[default]
    Preferred,
    /// Not requested.
    Discouraged,
}

impl UserVerification {
    /// The WebAuthn enum value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::Discouraged => "discouraged",
        }
    }
}

/// Attestation conveyance and trust (§10.2.4, OP-146 m.4 (d)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// Consumer default: nothing is requested and attestation is never a trust input.
    #[default]
    None,
    /// Enterprise: `direct` (or `enterprise`) attestation verified against fresh FIDO metadata
    /// and an AAGUID allowlist; stale metadata fails closed.
    Direct {
        /// Allowed authenticator models; empty allows every model the metadata vouches for.
        aaguids: Vec<Aaguid>,
        /// Request enterprise attestation instead of `direct`.
        enterprise: bool,
    },
}

impl AttestationPolicy {
    /// The `attestation` conveyance value.
    #[must_use]
    pub const fn conveyance(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Direct {
                enterprise: true, ..
            } => "enterprise",
            Self::Direct { .. } => "direct",
        }
    }
}

/// What a signature-counter regression on a device-bound credential does (§10.2.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SignCountAction {
    /// Accept and raise a signal.
    #[default]
    Signal,
    /// Reject and raise a signal.
    Reject,
}

/// A realm's WebAuthn policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmPolicy {
    /// User verification.
    pub user_verification: UserVerification,
    /// Attestation.
    pub attestation: AttestationPolicy,
    /// Enterprise policy: only BE = 0 credentials (IDI-5).
    pub require_device_bound: bool,
    /// Counter regressions on BE = 0 credentials.
    pub sign_count: SignCountAction,
    /// Accept RS256 for legacy authenticators (session login only).
    pub allow_rs256: bool,
    /// Whether the platform's own user verification counts as a factor; regulated templates
    /// such as TR payments set this to false (MD-11).
    pub platform_uv_is_factor: bool,
    /// Ceremony lifetime in seconds (PD).
    pub ceremony_ttl: u64,
}

impl Default for RealmPolicy {
    fn default() -> Self {
        Self {
            user_verification: UserVerification::Preferred,
            attestation: AttestationPolicy::None,
            require_device_bound: false,
            sign_count: SignCountAction::Signal,
            allow_rs256: true,
            platform_uv_is_factor: true,
            ceremony_ttl: 300,
        }
    }
}

impl RealmPolicy {
    /// The algorithms this realm offers, in preference order.
    #[must_use]
    pub fn algorithms(&self) -> Vec<CoseAlgorithm> {
        CoseAlgorithm::PREFERENCE
            .into_iter()
            .filter(|a| self.allow_rs256 || *a != CoseAlgorithm::Rs256)
            .collect()
    }
}
