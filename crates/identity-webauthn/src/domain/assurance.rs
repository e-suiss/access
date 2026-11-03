//! What a passkey can satisfy: binding class, AAL and CT ceilings (§10.2, IDP-8), independence
//! groups (TN-63) and the hardware-key registration rule (§10.2.5).

use super::cose::CoseAlgorithm;
use super::credential::CredentialRecord;
use super::ids::{Aaguid, CredentialId};

/// Device-bound or synced, from the BE flag (§10.2, IDP-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// BE = 0: the key cannot leave the authenticator.
    DeviceBound,
    /// BE = 1: the provider may sync the key.
    Synced,
}

impl Binding {
    /// From the BE flag.
    #[must_use]
    pub const fn from_backup_eligible(be: bool) -> Self {
        if be { Self::Synced } else { Self::DeviceBound }
    }
}

/// Authenticator assurance level ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Aal {
    /// Single factor.
    Aal1,
    /// UV passkey, synced.
    Aal2,
    /// UV passkey, device-bound.
    Aal3,
}

/// The highest CT tier the authentication can contribute to (IDP-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CtCeiling {
    /// Satisfies no CT (RS256 legacy authenticators).
    None,
    /// Phishing-resistant proof.
    Ct1,
    /// Plus UV = 1.
    Ct2,
    /// Plus BE = 0 (device-bound, non-custodial).
    Ct3,
}

/// The assurance one WebAuthn authentication carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assurance {
    /// Binding class.
    pub binding: Binding,
    /// Whether UV counted as a factor.
    pub user_verified: bool,
    /// AAL ceiling.
    pub aal: Aal,
    /// CT ceiling.
    pub ct: CtCeiling,
    /// RS256: only a session-login `authentication` Claim, never a `KeyBinding` (§10.2.4).
    pub session_login_only: bool,
}

/// Classifies one authentication. `platform_uv_is_factor` is false under MD-11 templates.
#[must_use]
pub fn classify(
    alg: CoseAlgorithm,
    backup_eligible: bool,
    user_verified: bool,
    platform_uv_is_factor: bool,
) -> Assurance {
    let binding = Binding::from_backup_eligible(backup_eligible);
    let uv = user_verified && platform_uv_is_factor;
    let (aal, ct) = match (uv, binding) {
        (false, _) => (Aal::Aal1, CtCeiling::Ct1),
        (true, Binding::Synced) => (Aal::Aal2, CtCeiling::Ct2),
        (true, Binding::DeviceBound) => (Aal::Aal3, CtCeiling::Ct3),
    };
    let legacy = alg == CoseAlgorithm::Rs256;
    Assurance {
        binding,
        user_verified: uv,
        aal,
        ct: if legacy { CtCeiling::None } else { ct },
        session_login_only: legacy,
    }
}

/// Credentials in one group count as one authenticator (TN-63).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IndependenceGroup {
    /// Synced passkeys of one provider fabric, keyed by AAGUID.
    Synced(Aaguid),
    /// A device-bound credential is its own group.
    Device(CredentialId),
}

/// The independence group of a credential (AAGUID + BE/BS; TN-63).
#[must_use]
pub fn independence_group(credential: &CredentialRecord) -> IndependenceGroup {
    if credential.backup_eligible {
        IndependenceGroup::Synced(credential.aaguid)
    } else {
        IndependenceGroup::Device(credential.id.clone())
    }
}

/// Account protection as shown to the user (§12.3.2 rules 1–2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protection {
    /// Distinct independence groups among live passkeys.
    pub groups: usize,
    /// Two independent paths exist; a synced passkey alone never qualifies.
    pub fully_protected: bool,
}

/// Counts independent passkey groups plus `other_paths` (recovery codes, a recovery contact).
#[must_use]
pub fn protection(credentials: &[CredentialRecord], other_paths: usize) -> Protection {
    let mut groups: Vec<IndependenceGroup> = Vec::new();
    for c in credentials.iter().filter(|c| c.deleted_at.is_none()) {
        let g = independence_group(c);
        if !groups.contains(&g) {
            groups.push(g);
        }
    }
    Protection {
        groups: groups.len(),
        fully_protected: groups.len().saturating_add(other_paths) >= 2,
    }
}

/// The hardware-key registration rule (§10.2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareKeyAdvice {
    /// At least two device-bound credentials.
    Satisfied,
    /// Fewer than two; a second registration is recommended.
    Recommended,
    /// Fewer than two on a break-glass account, where two are mandatory.
    Required,
}

/// At least two hardware-key registrations per user are recommended, and mandatory for
/// enterprise break-glass accounts (§10.2.5).
#[must_use]
pub fn hardware_key_rule(credentials: &[CredentialRecord], break_glass: bool) -> HardwareKeyAdvice {
    let device_bound = credentials
        .iter()
        .filter(|c| c.deleted_at.is_none() && !c.backup_eligible)
        .count();
    if device_bound >= 2 {
        HardwareKeyAdvice::Satisfied
    } else if break_glass {
        HardwareKeyAdvice::Required
    } else {
        HardwareKeyAdvice::Recommended
    }
}
