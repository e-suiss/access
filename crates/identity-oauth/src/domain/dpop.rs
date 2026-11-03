//! The realm's DPoP profile (§10.4.3, §12.2.1, MD-18, IDP-11): which algorithms and time
//! windows proofs are checked with, how a failure is answered, and how codes, refresh tokens
//! and access tokens are bound to the proof key (TN-27, TN-31).

use std::collections::BTreeSet;

use access_kernel::verify::cose::Algorithm;
use access_kernel::verify::dpop::{jkt_text, parse_jkt};
use access_kernel::verify::projection::Confirmation;

pub use access_crypto::dpop::Role;
pub use access_kernel::verify::dpop::Step;

/// The RFC 7638 thumbprint of a proof key: the value of `cnf.jkt` and `dpop_jkt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Jkt(pub [u8; 32]);

impl Jkt {
    /// From its base64url text.
    ///
    /// # Errors
    /// [`BindingError::Malformed`].
    pub fn parse(text: &str) -> Result<Self, BindingError> {
        parse_jkt(text)
            .map(Self)
            .map_err(|_| BindingError::Malformed)
    }

    /// Its base64url text.
    #[must_use]
    pub fn text(&self) -> String {
        jkt_text(&self.0)
    }
}

/// Why a DPoP profile is not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// No algorithm, or one outside `ES256` and `Ed25519` (MD-3).
    #[error("algorithms")]
    Algorithms,
    /// A window is zero or overflows.
    #[error("window")]
    Window,
}

/// Algorithms and time windows of a realm's proof checks; values PD (TN-29, TN-30).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpopProfile {
    allowed: BTreeSet<Algorithm>,
    lifetime_ms: u64,
    skew_ms: u64,
}

impl DpopProfile {
    /// Default proof lifetime after `iat` (§10.4.3 m.3 example).
    pub const DEFAULT_LIFETIME_MS: u64 = 5_000;
    /// Default clock skew; the server nonce, not the client clock, bounds freshness.
    pub const DEFAULT_SKEW_MS: u64 = 60_000;

    /// A profile over `allowed` algorithms, from the client or realm metadata (MD-3).
    ///
    /// # Errors
    /// [`ProfileError`].
    pub fn new(
        allowed: BTreeSet<Algorithm>,
        lifetime_ms: u64,
        skew_ms: u64,
    ) -> Result<Self, ProfileError> {
        if allowed.is_empty()
            || allowed
                .iter()
                .any(|a| !matches!(a, Algorithm::Es256 | Algorithm::Ed25519))
        {
            return Err(ProfileError::Algorithms);
        }
        let profile = Self {
            allowed,
            lifetime_ms,
            skew_ms,
        };
        if lifetime_ms == 0 || profile.replay_ttl_ms().is_none() {
            return Err(ProfileError::Window);
        }
        Ok(profile)
    }

    /// The allowed algorithms.
    #[must_use]
    pub const fn allowed(&self) -> &BTreeSet<Algorithm> {
        &self.allowed
    }

    /// Proof lifetime after `iat`.
    #[must_use]
    pub const fn lifetime_ms(&self) -> u64 {
        self.lifetime_ms
    }

    /// Clock skew tolerance.
    #[must_use]
    pub const fn skew_ms(&self) -> u64 {
        self.skew_ms
    }

    /// How long a replay key must be kept: proof lifetime + 2 × skew (TN-30).
    #[must_use]
    pub fn replay_ttl_ms(&self) -> Option<u64> {
        self.skew_ms
            .checked_mul(2)
            .and_then(|s| s.checked_add(self.lifetime_ms))
    }

    /// `dpop_signing_alg_values_supported`, by RFC 9864 fully-specified names; `EdDSA` is
    /// never announced (AG-38, OP-144).
    #[must_use]
    pub fn signing_alg_values(&self) -> Vec<&'static str> {
        self.allowed
            .iter()
            .filter_map(|a| match a {
                Algorithm::Es256 => Some("ES256"),
                Algorithm::Ed25519 => Some("Ed25519"),
                _ => None,
            })
            .collect()
    }
}

impl Default for DpopProfile {
    fn default() -> Self {
        Self {
            allowed: [Algorithm::Es256, Algorithm::Ed25519].into_iter().collect(),
            lifetime_ms: Self::DEFAULT_LIFETIME_MS,
            skew_ms: Self::DEFAULT_SKEW_MS,
        }
    }
}

/// Why a request's DPoP proof is not accepted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// The proof fails a step of the profile, or was seen before.
    #[error("invalid DPoP proof at {step:?}: {code}")]
    InvalidProof {
        /// The failed step.
        step: Step,
        /// Stable reason code.
        code: &'static str,
    },
    /// The nonce is missing or not current; the client retries with this one (TN-29).
    #[error("use DPoP nonce")]
    UseNonce {
        /// The nonce to send in `DPoP-Nonce`.
        nonce: String,
    },
    /// Trusted time, the nonce key or the replay cache is unavailable; the proof is rejected
    /// (TN-30, MD-8).
    #[error("DPoP state unavailable")]
    Unavailable,
}

impl Failure {
    /// The OAuth error code (RFC 9449 §7.1, §8, §9).
    #[must_use]
    pub const fn error(&self) -> &'static str {
        match self {
            Self::InvalidProof { .. } => "invalid_dpop_proof",
            Self::UseNonce { .. } => "use_dpop_nonce",
            Self::Unavailable => "temporarily_unavailable",
        }
    }

    /// The HTTP status: `400` at the authorization server, `401` with a `DPoP` challenge at a
    /// resource server, `503` when state is unavailable (TN-29, §10.4.3 m.2).
    #[must_use]
    pub const fn status(&self, role: Role) -> u16 {
        match (self, role) {
            (Self::Unavailable, _) => 503,
            (_, Role::AuthorizationServer) => 400,
            (_, Role::ResourceServer) => 401,
        }
    }

    /// The `DPoP-Nonce` header value to send with the error, if any.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        match self {
            Self::UseNonce { nonce } => Some(nonce),
            _ => None,
        }
    }

    /// The resource server's `WWW-Authenticate` value (RFC 9449 §7.1); `None` at the
    /// authorization server or when state is unavailable.
    #[must_use]
    pub fn challenge(&self, role: Role, profile: &DpopProfile) -> Option<String> {
        if role != Role::ResourceServer || matches!(self, Self::Unavailable) {
            return None;
        }
        Some(format!(
            r#"DPoP error="{}", algs="{}""#,
            self.error(),
            profile.signing_alg_values().join(" ")
        ))
    }
}

/// Whether a client can keep a secret (RFC 6749 §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientType {
    /// Browser, mobile or native: its refresh token is bound to the proof key (TN-31).
    Public,
    /// Authenticates at the token endpoint; client authentication suffices for refresh.
    Confidential,
}

/// Why a code, refresh token or access token cannot be bound or used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BindingError {
    /// `dpop_jkt` is not base64url of a SHA-256 thumbprint.
    #[error("malformed dpop_jkt")]
    Malformed,
    /// A DPoP proof is required and none was presented.
    #[error("proof required")]
    ProofRequired,
    /// The proof key is not the bound key.
    #[error("key mismatch")]
    KeyMismatch,
}

impl BindingError {
    /// The OAuth error code: `invalid_request` for a bad parameter, `invalid_dpop_proof`
    /// otherwise (RFC 9449 §10).
    #[must_use]
    pub const fn error(self) -> &'static str {
        match self {
            Self::Malformed => "invalid_request",
            Self::ProofRequired | Self::KeyMismatch => "invalid_dpop_proof",
        }
    }
}

/// The `dpop_jkt` authorization request parameter, which binds the code to a key
/// (RFC 9449 §10, TN-31).
///
/// # Errors
/// [`BindingError::Malformed`].
pub fn authorization_request_jkt(param: Option<&str>) -> Result<Option<Jkt>, BindingError> {
    param.map(Jkt::parse).transpose()
}

/// A code bound with `dpop_jkt` is redeemed only with a proof of that key (RFC 9449 §10.1).
///
/// # Errors
/// [`BindingError`].
pub fn check_code_exchange(code: Option<Jkt>, proof: Option<Jkt>) -> Result<(), BindingError> {
    match (code, proof) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(BindingError::ProofRequired),
        (Some(bound), Some(key)) if bound == key => Ok(()),
        (Some(_), Some(_)) => Err(BindingError::KeyMismatch),
    }
}

/// The key a new refresh token is bound to: the proof key for a public client, which must
/// present one; none for a confidential client (§10.4.3 m.4, TN-31, RFC 9449 §5).
///
/// # Errors
/// [`BindingError::ProofRequired`].
pub fn refresh_binding(
    client: ClientType,
    proof: Option<Jkt>,
) -> Result<Option<Jkt>, BindingError> {
    match client {
        ClientType::Public => proof.map(Some).ok_or(BindingError::ProofRequired),
        ClientType::Confidential => Ok(None),
    }
}

/// A bound refresh token is used only with a proof of its key; key loss means signing in
/// again (§12.2.1, TN-31).
///
/// # Errors
/// [`BindingError`].
pub fn check_refresh(bound: Option<Jkt>, proof: Option<Jkt>) -> Result<(), BindingError> {
    check_code_exchange(bound, proof)
}

/// The `cnf` of an identity plane access token: the DPoP key, else the mTLS certificate;
/// there is no bearer token (TN-27, PI-11).
///
/// # Errors
/// [`BindingError::ProofRequired`].
pub fn access_token_confirmation(
    proof: Option<Jkt>,
    mtls: Option<[u8; 32]>,
) -> Result<Confirmation, BindingError> {
    match (proof, mtls) {
        (Some(jkt), _) => Ok(Confirmation::Jkt(jkt.0)),
        (None, Some(x5t)) => Ok(Confirmation::X5tS256(x5t)),
        (None, None) => Err(BindingError::ProofRequired),
    }
}

#[cfg(test)]
mod tests;
