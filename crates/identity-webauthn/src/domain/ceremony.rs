//! Registration and authentication ceremony verification (WebAuthn L3 §7.1, §7.2; §10.2.4).
//! Pure: the caller supplies the issued state, the stored credential, metadata and time.

use access_crypto::webauthn::sha256;
use serde::Deserialize;

use super::Rejection;
use super::assurance::{Assurance, classify};
use super::attestation::{AttestationObject, verify_attestation};
use super::authenticator_data::{AuthenticatorData, Flags};
use super::client_data::{CeremonyType, check_client_data};
use super::cose::{CoseAlgorithm, CoseKey};
use super::credential::{CredentialRecord, bounded_transports};
use super::ids::{CredentialId, RealmId, UserHandle};
use super::mds::MdsBlob;
use super::policy::{RealmPolicy, SignCountAction, UserVerification};
use super::prf::{PrfConfig, PrfSalt};
use super::rp::RelyingParty;

/// Server-side state of a registration, kept by the caller and used once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationState {
    /// The realm.
    pub realm: RealmId,
    /// The account.
    pub user: UserHandle,
    /// The issued challenge.
    pub challenge: [u8; 32],
    /// Conditional create: UP may be 0 (WebAuthn L3 §7.1 step 14).
    pub conditional: bool,
    /// Unix seconds after which the state is void.
    pub expires_at: u64,
    /// PRF salt offered with the creation options.
    pub prf_salt: Option<PrfSalt>,
}

/// Server-side state of an authentication, kept by the caller and used once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationState {
    /// The realm.
    pub realm: RealmId,
    /// The issued challenge.
    pub challenge: [u8; 32],
    /// The account when the identifier was known; `None` on the discoverable path.
    pub user: Option<UserHandle>,
    /// The `allowCredentials` IDs sent; empty on the discoverable path.
    pub allowed: Vec<CredentialId>,
    /// UV demanded by the step (CT2+/AAL2+ need it), on top of the realm policy.
    pub require_user_verification: bool,
    /// Unix seconds after which the state is void.
    pub expires_at: u64,
}

/// Client extension results the server reads. PRF results are not part of this type: they
/// are dropped on parse and never stored (§10.2.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientExtensionResults {
    /// `credProps.rk`.
    pub cred_props_rk: Option<bool>,
    /// `prf.enabled`.
    pub prf_enabled: Option<bool>,
}

#[derive(Deserialize)]
struct RawExtensions {
    #[serde(rename = "credProps")]
    cred_props: Option<RawCredProps>,
    prf: Option<RawPrf>,
}

#[derive(Deserialize)]
struct RawCredProps {
    rk: Option<bool>,
}

#[derive(Deserialize)]
struct RawPrf {
    enabled: Option<bool>,
}

impl ClientExtensionResults {
    /// Ceiling for the JSON (CR-10).
    pub const MAX_LEN: usize = 4096;

    /// Reads `getClientExtensionResults()` JSON. Members other than `credProps.rk` and
    /// `prf.enabled` are discarded, PRF output included.
    ///
    /// # Errors
    /// [`Rejection::ClientData`].
    pub fn from_json(raw: &[u8]) -> Result<Self, Rejection> {
        access_parse::json::check(raw, Self::MAX_LEN, access_parse::json::MAX_DEPTH)
            .map_err(|_| Rejection::ClientData)?;
        let parsed: RawExtensions =
            serde_json::from_slice(raw).map_err(|_| Rejection::ClientData)?;
        Ok(Self {
            cred_props_rk: parsed.cred_props.and_then(|c| c.rk),
            prf_enabled: parsed.prf.and_then(|p| p.enabled),
        })
    }
}

/// What the browser returned from `navigator.credentials.create()`.
pub struct RegistrationResponse<'a> {
    /// `rawId`.
    pub raw_id: &'a [u8],
    /// `response.clientDataJSON`.
    pub client_data_json: &'a [u8],
    /// `response.attestationObject`.
    pub attestation_object: &'a [u8],
    /// `response.getTransports()`.
    pub transports: &'a [String],
    /// `getClientExtensionResults()`.
    pub extensions: ClientExtensionResults,
}

/// What the browser returned from `navigator.credentials.get()`.
pub struct AssertionResponse<'a> {
    /// `rawId`.
    pub raw_id: &'a [u8],
    /// `response.clientDataJSON`.
    pub client_data_json: &'a [u8],
    /// `response.authenticatorData`.
    pub authenticator_data: &'a [u8],
    /// `response.signature`.
    pub signature: &'a [u8],
    /// `response.userHandle`.
    pub user_handle: Option<&'a [u8]>,
}

fn uv_needed(policy: &RealmPolicy, extra: bool) -> bool {
    extra || policy.user_verification == UserVerification::Required
}

fn algorithm_allowed(policy: &RealmPolicy, alg: CoseAlgorithm) -> bool {
    policy.allow_rs256 || alg != CoseAlgorithm::Rs256
}

/// Verifies a registration and returns the record to store.
///
/// # Errors
/// [`Rejection`].
pub fn verify_registration(
    rp: &RelyingParty,
    policy: &RealmPolicy,
    state: &RegistrationState,
    response: &RegistrationResponse<'_>,
    metadata: Option<&MdsBlob>,
    now: u64,
) -> Result<CredentialRecord, Rejection> {
    if now > state.expires_at {
        return Err(Rejection::Expired);
    }
    // IDP-5, TN-17
    if !rp.pinned {
        return Err(Rejection::RpIdNotPinned);
    }
    let client = check_client_data(
        response.client_data_json,
        CeremonyType::Create,
        &state.challenge,
        rp,
    )?;
    let object = AttestationObject::parse(response.attestation_object)?;
    let auth = AuthenticatorData::parse(object.auth_data)?;
    if auth.rp_id_hash != sha256(rp.rp_id.as_str().as_bytes()) {
        return Err(Rejection::RpIdHash);
    }
    if !auth.flags.user_present() && !state.conditional {
        return Err(Rejection::UserPresence);
    }
    if uv_needed(policy, false) && !auth.flags.user_verified() {
        return Err(Rejection::UserVerification);
    }
    check_backup_flags(auth.flags, policy)?;
    let credential = auth
        .attested
        .as_ref()
        .ok_or(Rejection::AttestedCredential)?;
    if credential.credential_id.as_bytes() != response.raw_id {
        return Err(Rejection::AttestedCredential);
    }
    if !algorithm_allowed(policy, credential.public_key.alg()) {
        return Err(Rejection::Algorithm);
    }
    let attestation = verify_attestation(
        &object,
        &auth,
        &client.hash,
        &policy.attestation,
        metadata,
        now,
    )?;
    let prf = match (response.extensions.prf_enabled, state.prf_salt) {
        (Some(enabled), Some(salt)) => Some(PrfConfig::new(enabled, salt)),
        _ => None,
    };
    Ok(CredentialRecord {
        realm: state.realm,
        id: credential.credential_id.clone(),
        user: state.user,
        public_key: credential.public_key_raw.to_vec(),
        alg: credential.public_key.alg(),
        sign_count: auth.sign_count,
        backup_eligible: auth.flags.backup_eligible(),
        backup_state: auth.flags.backed_up(),
        user_verified: auth.flags.user_verified(),
        aaguid: credential.aaguid,
        transports: bounded_transports(response.transports),
        attestation,
        cred_protect: auth.extensions.cred_protect,
        discoverable: response.extensions.cred_props_rk,
        prf,
        created_at: now,
        last_used_at: None,
        deleted_at: None,
    })
}

fn check_backup_flags(flags: Flags, policy: &RealmPolicy) -> Result<(), Rejection> {
    // IDI-5
    if !flags.backup_consistent() {
        return Err(Rejection::BackupState);
    }
    if policy.require_device_bound && flags.backup_eligible() {
        return Err(Rejection::DeviceBoundRequired);
    }
    Ok(())
}

/// A risk signal from an authentication (TN-63, Ek B K14). Signals become Claims in Stage 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// BE = 0 and the counter did not advance (§10.2.4).
    SignCountRegressed {
        /// Stored counter.
        stored: u32,
        /// Presented counter.
        presented: u32,
    },
    /// BS went 1 → 0: warn (IDI-5).
    BackupStateLost,
    /// BS went 0 → 1 (TN-63).
    BackupStateGained,
}

/// The outcome of a verified assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// What the authentication can satisfy.
    pub assurance: Assurance,
    /// The counter to store.
    pub sign_count: u32,
    /// The BS flag to store.
    pub backup_state: bool,
    /// Signals to raise.
    pub signals: Vec<Signal>,
}

/// The sign-count rule (§10.2.4): with BE = 0 the counter must grow unless both values are zero
/// (the authenticator has no counter); with BE = 1 it is not required.
#[must_use]
pub fn sign_count_regressed(backup_eligible: bool, stored: u32, presented: u32) -> bool {
    !backup_eligible && (stored != 0 || presented != 0) && presented <= stored
}

/// Verifies an assertion against the stored credential.
///
/// # Errors
/// [`Rejection`]; [`Rejection::SignCount`] only when the realm rejects regressions.
pub fn verify_assertion(
    rp: &RelyingParty,
    policy: &RealmPolicy,
    state: &AuthenticationState,
    response: &AssertionResponse<'_>,
    stored: &CredentialRecord,
    now: u64,
) -> Result<VerifiedAssertion, Rejection> {
    if now > state.expires_at {
        return Err(Rejection::Expired);
    }
    if stored.deleted_at.is_some()
        || stored.realm != state.realm
        || stored.id.as_bytes() != response.raw_id
    {
        return Err(Rejection::UnknownCredential);
    }
    if !state.allowed.is_empty() && !state.allowed.contains(&stored.id) {
        return Err(Rejection::UnknownCredential);
    }
    match response.user_handle {
        Some(h) if UserHandle::from_slice(h) != Some(stored.user) => {
            return Err(Rejection::UserHandle);
        }
        None if state.user.is_none() => return Err(Rejection::UserHandle),
        _ => {}
    }
    if state.user.is_some_and(|u| u != stored.user) {
        return Err(Rejection::UserHandle);
    }
    let client = check_client_data(
        response.client_data_json,
        CeremonyType::Get,
        &state.challenge,
        rp,
    )?;
    let auth = AuthenticatorData::parse(response.authenticator_data)?;
    if auth.rp_id_hash != sha256(rp.rp_id.as_str().as_bytes()) {
        return Err(Rejection::RpIdHash);
    }
    if !auth.flags.user_present() {
        return Err(Rejection::UserPresence);
    }
    if uv_needed(policy, state.require_user_verification) && !auth.flags.user_verified() {
        return Err(Rejection::UserVerification);
    }
    // IDI-5
    if auth.flags.backup_eligible() != stored.backup_eligible {
        return Err(Rejection::BackupEligibility);
    }
    check_backup_flags(auth.flags, policy)?;
    let key = CoseKey::from_bytes(&stored.public_key)?;
    if key.alg() != stored.alg || !algorithm_allowed(policy, key.alg()) {
        return Err(Rejection::Algorithm);
    }
    let mut message = auth.raw.to_vec();
    message.extend_from_slice(&client.hash);
    key.verify(&message, response.signature)?;
    let mut signals = Vec::new();
    let mut sign_count = auth.sign_count.max(stored.sign_count);
    if sign_count_regressed(stored.backup_eligible, stored.sign_count, auth.sign_count) {
        signals.push(Signal::SignCountRegressed {
            stored: stored.sign_count,
            presented: auth.sign_count,
        });
        if policy.sign_count == SignCountAction::Reject {
            return Err(Rejection::SignCount);
        }
        sign_count = stored.sign_count;
    }
    match (stored.backup_state, auth.flags.backed_up()) {
        (true, false) => signals.push(Signal::BackupStateLost),
        (false, true) => signals.push(Signal::BackupStateGained),
        _ => {}
    }
    Ok(VerifiedAssertion {
        assurance: classify(
            key.alg(),
            stored.backup_eligible,
            auth.flags.user_verified(),
            policy.platform_uv_is_factor,
        ),
        sign_count,
        backup_state: auth.flags.backed_up(),
        signals,
    })
}
