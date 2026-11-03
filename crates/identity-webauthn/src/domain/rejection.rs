//! Why a ceremony is refused. A rejection is a decision, not an error (OP-64); the HTTP layer
//! shows one neutral message before authentication (CR-40, TN-82) and keeps the code for audit.

use access_parse::cbor::CborError;

/// A protocol rejection of a WebAuthn ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// The attestation object or authenticator data is not acceptable CBOR (CR-10).
    #[error("malformed CBOR: {0}")]
    Cbor(CborError),
    /// `clientDataJSON` is not acceptable JSON or misses a member.
    #[error("malformed client data")]
    ClientData,
    /// `clientDataJSON.type` is not the expected ceremony.
    #[error("wrong ceremony type")]
    CeremonyType,
    /// The challenge does not match the one issued.
    #[error("challenge mismatch")]
    Challenge,
    /// The ceremony state has expired.
    #[error("ceremony expired")]
    Expired,
    /// The origin is not the realm's RP ID, a subdomain of it or a declared related origin.
    #[error("origin not allowed")]
    Origin,
    /// The ceremony ran in a cross-origin frame.
    #[error("cross-origin ceremony")]
    CrossOrigin,
    /// `rpIdHash` is not SHA-256 of the realm's RP ID.
    #[error("RP ID hash mismatch")]
    RpIdHash,
    /// The realm's RP ID is not pinned yet (IDP-5, TN-17).
    #[error("RP ID not pinned")]
    RpIdNotPinned,
    /// User presence was not asserted.
    #[error("user presence missing")]
    UserPresence,
    /// User verification was required and not performed.
    #[error("user verification missing")]
    UserVerification,
    /// Authenticator data is malformed.
    #[error("malformed authenticator data")]
    AuthenticatorData,
    /// Registration without attested credential data, or a credential ID mismatch.
    #[error("attested credential data missing or inconsistent")]
    AttestedCredential,
    /// The credential public key is malformed or unsupported.
    #[error("unacceptable credential public key")]
    CoseKey,
    /// The key's algorithm is not allowed for this realm.
    #[error("algorithm not allowed")]
    Algorithm,
    /// The signature does not verify.
    #[error("invalid signature")]
    Signature,
    /// The attestation format is malformed or not supported by the realm's policy.
    #[error("attestation format not accepted")]
    AttestationFormat,
    /// The attestation statement does not verify.
    #[error("attestation statement invalid")]
    AttestationStatement,
    /// The attestation does not chain to a root from the metadata service.
    #[error("attestation not trusted")]
    AttestationTrust,
    /// The realm requires `direct` attestation and no fresh metadata is available (fail-closed).
    #[error("metadata unavailable")]
    MetadataUnavailable,
    /// The AAGUID is not on the realm's allowlist.
    #[error("authenticator model not allowed")]
    AaguidNotAllowed,
    /// The metadata service reports the authenticator model as compromised or revoked.
    #[error("authenticator model compromised")]
    AuthenticatorStatus,
    /// The realm requires device-bound credentials (BE = 0).
    #[error("device-bound credential required")]
    DeviceBoundRequired,
    /// BE changed since registration (IDI-5).
    #[error("backup eligibility changed")]
    BackupEligibility,
    /// BE = 0 with BS = 1 (IDI-5).
    #[error("invalid backup state")]
    BackupState,
    /// The signature counter did not advance and the realm rejects that (§10.2.4).
    #[error("signature counter regressed")]
    SignCount,
    /// The credential is unknown, deleted or not on the allow list.
    #[error("unknown credential")]
    UnknownCredential,
    /// The user handle does not match the credential's account.
    #[error("user handle mismatch")]
    UserHandle,
    /// The credential is already registered.
    #[error("credential already registered")]
    CredentialExists,
}

impl Rejection {
    /// Stable reason code for problem details (RFC 9457) and audit.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Cbor(e) => e.code(),
            Self::ClientData => "webauthn-client-data",
            Self::CeremonyType => "webauthn-ceremony-type",
            Self::Challenge => "webauthn-challenge",
            Self::Expired => "webauthn-expired",
            Self::Origin => "webauthn-origin",
            Self::CrossOrigin => "webauthn-cross-origin",
            Self::RpIdHash => "webauthn-rp-id-hash",
            Self::RpIdNotPinned => "webauthn-rp-id-not-pinned",
            Self::UserPresence => "webauthn-user-presence",
            Self::UserVerification => "webauthn-user-verification",
            Self::AuthenticatorData => "webauthn-authenticator-data",
            Self::AttestedCredential => "webauthn-attested-credential",
            Self::CoseKey => "webauthn-cose-key",
            Self::Algorithm => "webauthn-algorithm",
            Self::Signature => "webauthn-signature",
            Self::AttestationFormat => "webauthn-attestation-format",
            Self::AttestationStatement => "webauthn-attestation-statement",
            Self::AttestationTrust => "webauthn-attestation-trust",
            Self::MetadataUnavailable => "webauthn-metadata-unavailable",
            Self::AaguidNotAllowed => "webauthn-aaguid-not-allowed",
            Self::AuthenticatorStatus => "webauthn-authenticator-status",
            Self::DeviceBoundRequired => "webauthn-device-bound-required",
            Self::BackupEligibility => "webauthn-backup-eligibility",
            Self::BackupState => "webauthn-backup-state",
            Self::SignCount => "webauthn-sign-count",
            Self::UnknownCredential => "webauthn-unknown-credential",
            Self::UserHandle => "webauthn-user-handle",
            Self::CredentialExists => "webauthn-credential-exists",
        }
    }
}

impl From<CborError> for Rejection {
    fn from(e: CborError) -> Self {
        Self::Cbor(e)
    }
}
