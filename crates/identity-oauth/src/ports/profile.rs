//! What the high-assurance and legacy client profiles need from outside (OP-155 m.3 (k)): the
//! client certificates the environment trusts and their revocation status (P9), the environment KEK that
//! opens a `client_secret_jwt` secret, the SAML assertions of an accepted upstream verified in
//! the parser worker (P1, P2), and the environment's `jwe-enc` key that opens encrypted request
//! objects. Each default refuses (MD-8).

use access_store::client_profiles::SealedJwtSecret;
use access_store::identity::EnvironmentId;
pub use zeroize::Zeroizing;

pub use crate::domain::fapi::CertificateNames;
use crate::ports::oauth::Held;

/// Why a client certificate is not taken; every case refuses the client (MD-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CertificateRefused {
    /// The chain does not verify to a CA the environment trusts.
    #[error("untrusted")]
    Untrusted,
    /// The certificate is revoked.
    #[error("revoked")]
    Revoked,
    /// Revocation status is unknown, unreachable or stale.
    #[error("revocation unknown")]
    Unknown,
}

/// The environment's client certificate trust and revocation checks (P9, OP-155 m.3 (m)).
pub trait ClientCertificates: Send + Sync {
    /// The names of the leaf of `chain` (leaf first) once it verified for `environment` at `now_ms`.
    fn verify<'a>(
        &'a self,
        environment: &'a crate::ports::EnvironmentEntry,
        chain: &'a [Vec<u8>],
        now_ms: u64,
    ) -> Held<'a, Result<CertificateNames, CertificateRefused>>;
}

/// No trust anchors and no revocation checker: every PKI client certificate is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClientCertificates;

impl ClientCertificates for NoClientCertificates {
    fn verify<'a>(
        &'a self,
        _: &'a crate::ports::EnvironmentEntry,
        _: &'a [Vec<u8>],
        _: u64,
    ) -> Held<'a, Result<CertificateNames, CertificateRefused>> {
        Box::pin(async { Ok(Err(CertificateRefused::Unknown)) })
    }
}

/// The environment KEK, as it opens a `client_secret_jwt` secret (OP-148 m.16 (l)).
pub trait JwtSecrets: Send + Sync {
    /// The secret of client `client` of `environment`; `None` when it does not open.
    fn open<'a>(
        &'a self,
        environment: EnvironmentId,
        client: [u8; 16],
        sealed: &'a SealedJwtSecret,
    ) -> Held<'a, Option<Zeroizing<Vec<u8>>>>;
}

/// No environment KEK: every `client_secret_jwt` assertion is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoJwtSecrets;

impl JwtSecrets for NoJwtSecrets {
    fn open<'a>(
        &'a self,
        _: EnvironmentId,
        _: [u8; 16],
        _: &'a SealedJwtSecret,
    ) -> Held<'a, Option<Zeroizing<Vec<u8>>>> {
        Box::pin(async { Ok(None) })
    }
}

/// What a SAML 2.0 assertion of an accepted upstream showed, once the parser worker checked
/// it and its signature verified against the upstream's pinned keys (RFC 7522 §3, OP-155 m.3
/// (k)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlSubject {
    /// The upstream's entity ID, the assertion's `Issuer`.
    pub issuer: String,
    /// The `NameID`.
    pub name_id: String,
    /// The assertion `ID`, used once.
    pub id: String,
    /// `NotOnOrAfter` of the bearer `SubjectConfirmationData`, Unix milliseconds.
    pub not_on_or_after_ms: u64,
    /// The account the upstream identity is linked to in the environment, when there is one.
    pub subject: Option<[u8; 16]>,
}

/// Why a SAML assertion is not taken; every case answers `invalid_grant`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SamlRefused {
    /// Malformed, or refused by the worker's limits.
    #[error("malformed")]
    Malformed,
    /// The signature does not verify against the upstream's keys.
    #[error("signature")]
    Signature,
    /// Not an assertion of an accepted SAML upstream.
    #[error("issuer")]
    Issuer,
    /// Wrong audience or recipient, expired, not yet valid, or not a bearer confirmation.
    #[error("conditions")]
    Conditions,
}

/// SAML assertions verified in the parser worker (P1) by the SAML verifier (P2).
pub trait SamlAssertions: Send + Sync {
    /// The subject of the base64url `assertion` from upstream `upstream` of `environment`, addressed to
    /// `audience` (the token endpoint), at `now_ms`.
    fn verify<'a>(
        &'a self,
        environment: EnvironmentId,
        upstream: &'a str,
        assertion: &'a str,
        audience: &'a str,
        now_ms: u64,
    ) -> Held<'a, Result<SamlSubject, SamlRefused>>;
}

/// No SAML verifier: every SAML assertion is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSamlAssertions;

impl SamlAssertions for NoSamlAssertions {
    fn verify<'a>(
        &'a self,
        _: EnvironmentId,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: u64,
    ) -> Held<'a, Result<SamlSubject, SamlRefused>> {
        Box::pin(async { Ok(Err(SamlRefused::Issuer)) })
    }
}

/// The environment's `jwe-enc` key, as it opens request objects encrypted to the environment (OP-155 m.3
/// (k), `KeyPurpose::JweEnc`).
pub trait RequestKeys: Send + Sync {
    /// The plaintext of `jwe`; `None` when it does not open.
    fn decrypt<'a>(&'a self, environment: EnvironmentId, jwe: &'a str)
    -> Held<'a, Option<Vec<u8>>>;
}

/// No `jwe-enc` key: every encrypted request object is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRequestKeys;

impl RequestKeys for NoRequestKeys {
    fn decrypt<'a>(&'a self, _: EnvironmentId, _: &'a str) -> Held<'a, Option<Vec<u8>>> {
        Box::pin(async { Ok(None) })
    }
}
