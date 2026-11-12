//! The registry entry of a passkey: realm-local public material only (CMP-15.7, §7.1).

use super::cose::CoseAlgorithm;
use super::ids::{Aaguid, CredentialId, RealmId, UserHandle};
use super::prf::PrfConfig;

/// How the registration's attestation was treated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationKind {
    /// `none`.
    None,
    /// Another format under a `none` realm: kept as a hint, never verified or trusted.
    Unverified(String),
    /// A statement of this format verified against FIDO metadata and revocation (OP-159 m.3
    /// (ll)).
    Verified(String),
}

/// Ceiling for stored transports, and for the length of each.
pub const MAX_TRANSPORTS: usize = 8;
/// Ceiling for one transport string.
pub const MAX_TRANSPORT_LEN: usize = 32;

/// Keeps transport hints, unknown values included (§10.2.4), within fixed bounds.
#[must_use]
pub fn bounded_transports(transports: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in transports {
        if out.len() == MAX_TRANSPORTS {
            break;
        }
        if !t.is_empty() && t.len() <= MAX_TRANSPORT_LEN && !out.contains(t) {
            out.push(t.clone());
        }
    }
    out
}

/// A registered credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    /// The realm; credentials never cross realms.
    pub realm: RealmId,
    /// Credential ID.
    pub id: CredentialId,
    /// The account's WebAuthn `user.id`.
    pub user: UserHandle,
    /// `COSE_Key` bytes.
    pub public_key: Vec<u8>,
    /// The key's algorithm.
    pub alg: CoseAlgorithm,
    /// Last accepted signature counter.
    pub sign_count: u32,
    /// BE at registration; never changes (IDI-5).
    pub backup_eligible: bool,
    /// Last seen BS.
    pub backup_state: bool,
    /// Whether UV was performed at registration.
    pub user_verified: bool,
    /// Model hint.
    pub aaguid: Aaguid,
    /// Transport hints.
    pub transports: Vec<String>,
    /// Attestation treatment.
    pub attestation: AttestationKind,
    /// `credProtect` level the authenticator reported.
    pub cred_protect: Option<u8>,
    /// `credProps.rk` as the client reported it.
    pub discoverable: Option<bool>,
    /// PRF salts; never PRF output.
    pub prf: Option<PrfConfig>,
    /// Registration time, Unix seconds.
    pub created_at: u64,
    /// Last successful authentication, Unix seconds.
    pub last_used_at: Option<u64>,
    /// Soft delete (OP-73).
    pub deleted_at: Option<u64>,
}
