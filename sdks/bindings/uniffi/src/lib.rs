//! uniffi binding of the Access Kernel for Swift, Kotlin and Python (OP-116).
//!
//! Structured values cross as canonical CBOR in `Vec<u8>` (`bytes` in Python, `Data` in Swift,
//! `ByteArray` in Kotlin), in the shapes of `conformance/cddl/kernel.cddl`; integers cross as
//! `u64`. A failure is a [`KernelError`]: one variant per stable name family, and its message is
//! exactly the stable name the conformance vectors use.

#![forbid(unsafe_code)]
#![allow(clippy::needless_pass_by_value)]

use access_kernel::binding::{self, Kind};

uniffi::setup_scaffolding!();

/// A Kernel failure; the message is the stable name (OP-116 m.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum KernelError {
    /// `Input` family.
    #[error("{0}")]
    Input(String),
    /// `Fuel` family.
    #[error("{0}")]
    Fuel(String),
    /// `Limit` family.
    #[error("{0}")]
    Limit(String),
    /// `Cbor` family.
    #[error("{0}")]
    Cbor(String),
    /// `Shape` family.
    #[error("{0}")]
    Shape(String),
    /// `Header` family.
    #[error("{0}")]
    Header(String),
    /// `Crit` family.
    #[error("{0}")]
    Crit(String),
    /// `Unprotected` family.
    #[error("{0}")]
    Unprotected(String),
    /// `Algorithm` family.
    #[error("{0}")]
    Algorithm(String),
    /// `UnknownKid` family.
    #[error("{0}")]
    UnknownKid(String),
    /// `KeyType` family.
    #[error("{0}")]
    KeyType(String),
    /// `ContentType` family.
    #[error("{0}")]
    ContentType(String),
    /// `HighS` family.
    #[error("{0}")]
    HighS(String),
    /// `Signature` family.
    #[error("{0}")]
    Signature(String),
    /// `UnknownBinding` family.
    #[error("{0}")]
    UnknownBinding(String),
    /// `Superseded` family.
    #[error("{0}")]
    Superseded(String),
    /// `OutsideBindingScope` family.
    #[error("{0}")]
    OutsideBindingScope(String),
    /// `DomainMismatch` family.
    #[error("{0}")]
    DomainMismatch(String),
    /// `Thumbprint` family.
    #[error("{0}")]
    Thumbprint(String),
    /// `Usage` family.
    #[error("{0}")]
    Usage(String),
    /// `Window` family.
    #[error("{0}")]
    Window(String),
    /// `Payload` family.
    #[error("{0}")]
    Payload(String),
    /// `Format` family.
    #[error("{0}")]
    Format(String),
    /// `Base64` family.
    #[error("{0}")]
    Base64(String),
    /// `Json` family.
    #[error("{0}")]
    Json(String),
    /// `Type` family.
    #[error("{0}")]
    Type(String),
    /// `Issuer` family.
    #[error("{0}")]
    Issuer(String),
    /// `Audience` family.
    #[error("{0}")]
    Audience(String),
    /// `Expired` family.
    #[error("{0}")]
    Expired(String),
    /// `NotYetValid` family.
    #[error("{0}")]
    NotYetValid(String),
    /// `Time` family.
    #[error("{0}")]
    Time(String),
    /// `HashAlgorithm` family.
    #[error("{0}")]
    HashAlgorithm(String),
    /// `Disclosure` family.
    #[error("{0}")]
    Disclosure(String),
    /// `Duplicate` family.
    #[error("{0}")]
    Duplicate(String),
    /// `Unreferenced` family.
    #[error("{0}")]
    Unreferenced(String),
    /// `Collision` family.
    #[error("{0}")]
    Collision(String),
    /// `KeyBinding` family.
    #[error("{0}")]
    KeyBinding(String),
    /// `ConfirmationKey` family.
    #[error("{0}")]
    ConfirmationKey(String),
    /// `Overflow` family.
    #[error("{0}")]
    Overflow(String),
    /// `MustUnderstand` family.
    #[error("{0}")]
    MustUnderstand(String),
    /// `Stale` family.
    #[error("{0}")]
    Stale(String),
    /// `OnlineRequired` family.
    #[error("{0}")]
    OnlineRequired(String),
}

impl From<binding::Error> for KernelError {
    fn from(e: binding::Error) -> Self {
        let name = e.name();
        match e.kind() {
            Kind::Input => Self::Input(name),
            Kind::Fuel => Self::Fuel(name),
            Kind::Limit => Self::Limit(name),
            Kind::Cbor => Self::Cbor(name),
            Kind::Shape => Self::Shape(name),
            Kind::Header => Self::Header(name),
            Kind::Crit => Self::Crit(name),
            Kind::Unprotected => Self::Unprotected(name),
            Kind::Algorithm => Self::Algorithm(name),
            Kind::UnknownKid => Self::UnknownKid(name),
            Kind::KeyType => Self::KeyType(name),
            Kind::ContentType => Self::ContentType(name),
            Kind::HighS => Self::HighS(name),
            Kind::Signature => Self::Signature(name),
            Kind::UnknownBinding => Self::UnknownBinding(name),
            Kind::Superseded => Self::Superseded(name),
            Kind::OutsideBindingScope => Self::OutsideBindingScope(name),
            Kind::DomainMismatch => Self::DomainMismatch(name),
            Kind::Thumbprint => Self::Thumbprint(name),
            Kind::Usage => Self::Usage(name),
            Kind::Window => Self::Window(name),
            Kind::Payload => Self::Payload(name),
            Kind::Format => Self::Format(name),
            Kind::Base64 => Self::Base64(name),
            Kind::Json => Self::Json(name),
            Kind::Type => Self::Type(name),
            Kind::Issuer => Self::Issuer(name),
            Kind::Audience => Self::Audience(name),
            Kind::Expired => Self::Expired(name),
            Kind::NotYetValid => Self::NotYetValid(name),
            Kind::Time => Self::Time(name),
            Kind::HashAlgorithm => Self::HashAlgorithm(name),
            Kind::Disclosure => Self::Disclosure(name),
            Kind::Duplicate => Self::Duplicate(name),
            Kind::Unreferenced => Self::Unreferenced(name),
            Kind::Collision => Self::Collision(name),
            Kind::KeyBinding => Self::KeyBinding(name),
            Kind::ConfirmationKey => Self::ConfirmationKey(name),
            Kind::Overflow => Self::Overflow(name),
            Kind::MustUnderstand => Self::MustUnderstand(name),
            Kind::Stale => Self::Stale(name),
            Kind::OnlineRequired => Self::OnlineRequired(name),
        }
    }
}

/// Kernel public API version as `"major.minor"`.
#[uniffi::export]
#[must_use]
pub fn api_version() -> String {
    binding::api_version()
}

/// `evaluation-input` and fuel to `decision` (OP-111, OP-116 m.5).
///
/// # Errors
/// `input`, `fuel` or `limit`.
#[uniffi::export]
pub fn evaluate(input: Vec<u8>, fuel: u64) -> Result<Vec<u8>, KernelError> {
    Ok(binding::evaluate(&input, fuel)?)
}

/// Child ⊆ Parent for a holder under a catalog (§5.8).
///
/// # Errors
/// `input`.
#[uniffi::export]
pub fn child_within_parent(
    child: Vec<u8>,
    parent: Vec<u8>,
    holder: Vec<u8>,
    catalog: Vec<u8>,
) -> Result<bool, KernelError> {
    Ok(binding::child_within_parent(
        &child, &parent, &holder, &catalog,
    )?)
}

/// `intent-envelope` to its `digest`.
///
/// # Errors
/// `input`.
#[uniffi::export]
pub fn intent_digest(envelope: Vec<u8>) -> Result<Vec<u8>, KernelError> {
    Ok(binding::intent_digest(&envelope)?)
}

/// Tagged `COSE_Sign1` and `key-set` to `{kid, payload}`.
///
/// # Errors
/// `input` or a COSE name.
#[uniffi::export]
pub fn verify_cose_sign1(
    sign1: Vec<u8>,
    key_set: Vec<u8>,
    content_type: String,
) -> Result<Vec<u8>, KernelError> {
    Ok(binding::verify_cose_sign1(&sign1, &key_set, &content_type)?)
}

/// Binding-signed Domain Metadata and trusted `key-set` to `domain-metadata`.
///
/// # Errors
/// `input` or a key-scope name.
#[uniffi::export]
pub fn verify_metadata(signed: Vec<u8>, trusted: Vec<u8>) -> Result<Vec<u8>, KernelError> {
    Ok(binding::verify_metadata(&signed, &trusted)?)
}

/// `domain-metadata`, artefact domain, signed excerpt, usage and `iat` to `operational-key`.
///
/// # Errors
/// `input` or a key-scope name.
#[uniffi::export]
pub fn operational_key(
    metadata: Vec<u8>,
    domain: Vec<u8>,
    excerpt: Vec<u8>,
    usage: String,
    iat: u64,
) -> Result<Vec<u8>, KernelError> {
    Ok(binding::operational_key(
        &metadata, &domain, &excerpt, &usage, iat,
    )?)
}

/// Access-native compact JWS to its payload JSON text, after the claim checks.
///
/// # Errors
/// `input`, a JWS name or a claim name.
#[uniffi::export]
pub fn verify_jws_compact(
    token: String,
    key_set: Vec<u8>,
    typ: String,
    issuer: String,
    audience: String,
    now: u64,
    skew_ms: u64,
) -> Result<String, KernelError> {
    Ok(binding::verify_jws_compact(
        &token, &key_set, &typ, &issuer, &audience, now, skew_ms,
    )?)
}

/// Access-native SD-JWT presentation to its disclosed claims JSON text.
///
/// # Errors
/// `input` or an SD-JWT name.
#[uniffi::export]
pub fn verify_sd_jwt(
    presentation: String,
    key_set: Vec<u8>,
    typ: String,
    audience: String,
    nonce: String,
    now: u64,
    skew_ms: u64,
) -> Result<String, KernelError> {
    Ok(binding::verify_sd_jwt(
        &presentation,
        &key_set,
        &typ,
        &audience,
        &nonce,
        now,
        skew_ms,
    )?)
}

/// Checks a `validity-contract` at the moment of use (§9.12).
///
/// # Errors
/// `input` or a validity name.
#[uniffi::export]
pub fn check_validity(
    contract: Vec<u8>,
    now: u64,
    audience: String,
    understood: Vec<String>,
    last_refresh: Option<u64>,
    online: bool,
    skew_ms: u64,
) -> Result<(), KernelError> {
    Ok(binding::check_validity(
        &contract,
        now,
        &audience,
        understood,
        last_refresh,
        online,
        skew_ms,
    )?)
}

/// RFC 9162 inclusion proof; `path` is the 32-byte hashes concatenated.
///
/// # Errors
/// `input`.
#[uniffi::export]
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf_hash: Vec<u8>,
    path: Vec<u8>,
    root: Vec<u8>,
) -> Result<bool, KernelError> {
    Ok(binding::verify_inclusion(
        index, size, &leaf_hash, &path, &root,
    )?)
}

/// RFC 9162 consistency proof; `path` is the 32-byte hashes concatenated.
///
/// # Errors
/// `input`.
#[uniffi::export]
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: Vec<u8>,
    second_root: Vec<u8>,
    path: Vec<u8>,
) -> Result<bool, KernelError> {
    Ok(binding::verify_consistency(
        first,
        second,
        &first_root,
        &second_root,
        &path,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_the_stable_name() {
        assert_eq!(api_version(), "0.0");
        assert_eq!(
            evaluate(vec![0xa0], 1_000_001),
            Err(KernelError::Input("input".to_owned()))
        );
        let e = verify_jws_compact(
            "a.b".to_owned(),
            vec![0xa0],
            String::new(),
            String::new(),
            String::new(),
            0,
            0,
        );
        assert_eq!(e, Err(KernelError::Input("input".to_owned())));
        assert_eq!(
            verify_inclusion(0, 1, vec![0; 32], vec![], vec![0; 32]),
            Ok(true)
        );
    }
}
