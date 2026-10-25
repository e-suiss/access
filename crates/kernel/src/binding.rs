//! Bytes-in, bytes-out surface shared by the Wasm and uniffi bindings (OP-116).
//!
//! Structured values cross as canonical CBOR in the `kernel.cddl` shapes the conformance vectors
//! use; scalars cross as text, `u64` and `bool`. Every failure is an [`Error`] whose
//! [`Display`](core::fmt::Display) text is the stable name the vectors use (OP-116 m.1).
//! Signatures are verified with [`PureBackend`] (OP-116 m.4, CR-54).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::algebra::{self, Catalog};
use crate::codec::{Canonical, map, word};
use crate::combinator::codec::{OwnedInput, decision_value};
use crate::combinator::{self, Fuel, Rejection};
use crate::digest::{self, Digest, Hash};
use crate::intent::{self, IntentEnvelope};
use crate::json::Json;
use crate::model::{CanonicalAuthority, SubjectSelector, TrustedTime};
use crate::validity::{self, ValidityContract, ValidityError, VerifierContext};
use crate::verify::PureBackend;
use crate::verify::SignatureError;
use crate::verify::cose::{self, CoseError, KeySet};
use crate::verify::jws::{self, ClaimError, ClaimRules, JwsError, Origin};
use crate::verify::key_scope::{self, DomainMetadata, KeyScopeError, USAGES};
use crate::verify::sd_jwt::{self, SdJwtError};

/// Largest step budget a caller may give [`evaluate`] (OP-116 m.5, OP-108 m.11). PD.
pub const MAX_FUEL: u64 = 1_000_000;

/// Why a binding call fails. The [`Display`](core::fmt::Display) text is the stable name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An argument is not a value of its contract, or the fuel is above [`MAX_FUEL`].
    Input,
    /// Step budget exhausted.
    Fuel,
    /// `COSE_Sign1` rejected.
    Cose(CoseError),
    /// Domain Metadata or operational key rejected.
    KeyScope(KeyScopeError),
    /// Compact JWS rejected.
    Jws(JwsError),
    /// JWT claims rejected.
    Claim(ClaimError),
    /// SD-JWT presentation rejected.
    SdJwt(SdJwtError),
    /// Validity contract does not allow use now.
    Validity(ValidityError),
}

/// The family of an [`Error`], one per stable name or name prefix; bindings map it to their
/// error variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `input`.
    Input,
    /// `fuel`.
    Fuel,
    /// COSE `cbor`.
    Cbor,
    /// COSE `shape`.
    Shape,
    /// COSE `header`; JWS `header not in profile`.
    Header,
    /// COSE `crit`.
    Crit,
    /// COSE `unprotected`.
    Unprotected,
    /// `algorithm`; JWS `algorithm not allowed`.
    Algorithm,
    /// COSE `unknown-kid`; JWS `unknown kid`.
    UnknownKid,
    /// COSE `key-type`; JWS `key type does not match algorithm`.
    KeyType,
    /// `content-type`.
    ContentType,
    /// COSE `high-s`; JWS `signature: high-S signature`.
    HighS,
    /// `signature`; JWS `signature: …`.
    Signature,
    /// `unknown-binding`.
    UnknownBinding,
    /// `superseded`.
    Superseded,
    /// `outside-binding-scope`.
    OutsideBindingScope,
    /// `domain-mismatch`.
    DomainMismatch,
    /// `thumbprint`.
    Thumbprint,
    /// `usage`.
    Usage,
    /// `window`.
    Window,
    /// `payload`; claims `payload: …`.
    Payload,
    /// `not a compact JWS`; `not an SD-JWT presentation`.
    Format,
    /// `bad base64url`.
    Base64,
    /// JWS `header: …`; SD-JWT `json: …`.
    Json,
    /// `unexpected typ`.
    Type,
    /// `issuer`.
    Issuer,
    /// `audience` (claims, validity).
    Audience,
    /// `expired` (claims, validity).
    Expired,
    /// `not yet valid` (claims); `not-yet-valid` (validity).
    NotYetValid,
    /// `bad time claim`.
    Time,
    /// `hash algorithm not allowed`.
    HashAlgorithm,
    /// `malformed disclosure`.
    Disclosure,
    /// `duplicate disclosure`.
    Duplicate,
    /// `unreferenced disclosure`.
    Unreferenced,
    /// `claim name collision`.
    Collision,
    /// `key binding mismatch`.
    KeyBinding,
    /// `bad confirmation key`.
    ConfirmationKey,
    /// `overflow`.
    Overflow,
    /// `must-understand`.
    MustUnderstand,
    /// `stale`.
    Stale,
    /// `online-required`.
    OnlineRequired,
}

const fn cose_name(e: CoseError) -> &'static str {
    match e {
        CoseError::Cbor(_) => "cbor",
        CoseError::Shape => "shape",
        CoseError::Header => "header",
        CoseError::Crit => "crit",
        CoseError::Unprotected => "unprotected",
        CoseError::Algorithm => "algorithm",
        CoseError::UnknownKid => "unknown-kid",
        CoseError::KeyType => "key-type",
        CoseError::ContentType => "content-type",
        CoseError::Signature(SignatureError::HighS) => "high-s",
        CoseError::Signature(_) => "signature",
    }
}

const fn cose_kind(e: CoseError) -> Kind {
    match e {
        CoseError::Cbor(_) => Kind::Cbor,
        CoseError::Shape => Kind::Shape,
        CoseError::Header => Kind::Header,
        CoseError::Crit => Kind::Crit,
        CoseError::Unprotected => Kind::Unprotected,
        CoseError::Algorithm => Kind::Algorithm,
        CoseError::UnknownKid => Kind::UnknownKid,
        CoseError::KeyType => Kind::KeyType,
        CoseError::ContentType => Kind::ContentType,
        CoseError::Signature(SignatureError::HighS) => Kind::HighS,
        CoseError::Signature(_) => Kind::Signature,
    }
}

const fn key_scope_name(e: KeyScopeError) -> &'static str {
    match e {
        KeyScopeError::Signature(CoseError::UnknownKid) => "unknown-binding",
        KeyScopeError::Signature(CoseError::Signature(_)) => "signature",
        KeyScopeError::Signature(other) => cose_name(other),
        KeyScopeError::Payload(_) => "payload",
        KeyScopeError::Superseded => "superseded",
        KeyScopeError::OutOfScope => "outside-binding-scope",
        KeyScopeError::DomainMismatch => "domain-mismatch",
        KeyScopeError::Thumbprint => "thumbprint",
        KeyScopeError::Algorithm => "algorithm",
        KeyScopeError::Usage => "usage",
        KeyScopeError::Window => "window",
    }
}

const fn key_scope_kind(e: KeyScopeError) -> Kind {
    match e {
        KeyScopeError::Signature(CoseError::UnknownKid) => Kind::UnknownBinding,
        KeyScopeError::Signature(CoseError::Signature(_)) => Kind::Signature,
        KeyScopeError::Signature(other) => cose_kind(other),
        KeyScopeError::Payload(_) => Kind::Payload,
        KeyScopeError::Superseded => Kind::Superseded,
        KeyScopeError::OutOfScope => Kind::OutsideBindingScope,
        KeyScopeError::DomainMismatch => Kind::DomainMismatch,
        KeyScopeError::Thumbprint => Kind::Thumbprint,
        KeyScopeError::Algorithm => Kind::Algorithm,
        KeyScopeError::Usage => Kind::Usage,
        KeyScopeError::Window => Kind::Window,
    }
}

const fn jws_kind(e: JwsError) -> Kind {
    match e {
        JwsError::Format => Kind::Format,
        JwsError::Base64 => Kind::Base64,
        JwsError::Json(_) => Kind::Json,
        JwsError::Header => Kind::Header,
        JwsError::Algorithm => Kind::Algorithm,
        JwsError::UnknownKid => Kind::UnknownKid,
        JwsError::KeyType => Kind::KeyType,
        JwsError::Type => Kind::Type,
        JwsError::Signature(SignatureError::HighS) => Kind::HighS,
        JwsError::Signature(_) => Kind::Signature,
    }
}

const fn claim_kind(e: ClaimError) -> Kind {
    match e {
        ClaimError::Json(_) => Kind::Payload,
        ClaimError::Issuer => Kind::Issuer,
        ClaimError::Audience => Kind::Audience,
        ClaimError::Expired => Kind::Expired,
        ClaimError::NotYetValid => Kind::NotYetValid,
        ClaimError::Time => Kind::Time,
    }
}

const fn sd_jwt_kind(e: SdJwtError) -> Kind {
    match e {
        SdJwtError::Format => Kind::Format,
        SdJwtError::Jws(j) => jws_kind(j),
        SdJwtError::Json(_) => Kind::Json,
        SdJwtError::HashAlgorithm => Kind::HashAlgorithm,
        SdJwtError::Disclosure => Kind::Disclosure,
        SdJwtError::Duplicate => Kind::Duplicate,
        SdJwtError::Unreferenced => Kind::Unreferenced,
        SdJwtError::Collision => Kind::Collision,
        SdJwtError::KeyBinding => Kind::KeyBinding,
        SdJwtError::ConfirmationKey => Kind::ConfirmationKey,
        SdJwtError::Claims(c) | SdJwtError::IssuerClaims(c) => claim_kind(c),
    }
}

const fn validity_name(e: ValidityError) -> &'static str {
    match e {
        ValidityError::Overflow => "overflow",
        ValidityError::Expired => "expired",
        ValidityError::NotYetValid => "not-yet-valid",
        ValidityError::Audience => "audience",
        ValidityError::MustUnderstand => "must-understand",
        ValidityError::Stale => "stale",
        ValidityError::OnlineRequired => "online-required",
    }
}

const fn validity_kind(e: ValidityError) -> Kind {
    match e {
        ValidityError::Overflow => Kind::Overflow,
        ValidityError::Expired => Kind::Expired,
        ValidityError::NotYetValid => Kind::NotYetValid,
        ValidityError::Audience => Kind::Audience,
        ValidityError::MustUnderstand => Kind::MustUnderstand,
        ValidityError::Stale => Kind::Stale,
        ValidityError::OnlineRequired => Kind::OnlineRequired,
    }
}

impl Error {
    /// The family of this error.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match *self {
            Self::Input => Kind::Input,
            Self::Fuel => Kind::Fuel,
            Self::Cose(e) => cose_kind(e),
            Self::KeyScope(e) => key_scope_kind(e),
            Self::Jws(e) => jws_kind(e),
            Self::Claim(e) => claim_kind(e),
            Self::SdJwt(e) => sd_jwt_kind(e),
            Self::Validity(e) => validity_kind(e),
        }
    }

    /// The stable name.
    #[must_use]
    pub fn name(&self) -> String {
        let mut out = String::new();
        let _ = write!(out, "{self}");
        out
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input => f.write_str("input"),
            Self::Fuel => f.write_str("fuel"),
            Self::Cose(e) => f.write_str(cose_name(*e)),
            Self::KeyScope(e) => f.write_str(key_scope_name(*e)),
            Self::Jws(e) => write!(f, "{e}"),
            Self::Claim(e) => write!(f, "{e}"),
            Self::SdJwt(e) => write!(f, "{e}"),
            Self::Validity(e) => f.write_str(validity_name(*e)),
        }
    }
}

impl core::error::Error for Error {}

const fn rejection(r: Rejection) -> Error {
    match r {
        Rejection::Input => Error::Input,
        Rejection::Fuel => Error::Fuel,
    }
}

fn decode<T: Canonical>(bytes: &[u8]) -> Result<T, Error> {
    T::from_bytes(bytes).map_err(|_| Error::Input)
}

fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    dcbor::encode(value, Limits::CEILING).map_err(|_| Error::Input)
}

fn hash(bytes: &[u8]) -> Result<Hash, Error> {
    Hash::try_from(bytes).map_err(|_| Error::Input)
}

fn hashes(bytes: &[u8]) -> Result<Vec<Hash>, Error> {
    let (chunks, rest) = bytes.as_chunks::<32>();
    if !rest.is_empty() {
        return Err(Error::Input);
    }
    Ok(chunks.to_vec())
}

/// Kernel public API version as `"major.minor"`.
#[must_use]
pub fn api_version() -> String {
    let mut out = String::new();
    let v = crate::API_VERSION;
    let _ = write!(out, "{}.{}", v.major, v.minor);
    out
}

/// Evaluates an `evaluation-input` with `fuel` steps and returns the canonical `decision`
/// (OP-111, OP-116 m.5).
///
/// # Errors
/// `input`, `fuel` or `limit`.
pub fn evaluate(input: &[u8], fuel: u64) -> Result<Vec<u8>, Error> {
    if fuel > MAX_FUEL {
        return Err(Error::Input);
    }
    let owned: OwnedInput = decode(input)?;
    let decision = combinator::evaluate(&owned.input(), &mut Fuel(fuel)).map_err(rejection)?;
    encode(&decision_value(&decision))
}

/// Whether `child` stays within `parent` when delegated to `holder` (§5.8). Arguments are a
/// `canonical-authority`, a `canonical-authority`, a `subject-selector` and a `catalog`.
///
/// # Errors
/// `input`.
pub fn child_within_parent(
    child: &[u8],
    parent: &[u8],
    holder: &[u8],
    catalog: &[u8],
) -> Result<bool, Error> {
    let child: CanonicalAuthority = decode(child)?;
    let parent: CanonicalAuthority = decode(parent)?;
    let holder: SubjectSelector = decode(holder)?;
    let catalog: Catalog = decode(catalog)?;
    Ok(algebra::child_within_parent(
        &child, &parent, &holder, &catalog,
    ))
}

/// The `digest` of an `intent-envelope` (OP-106 m.22).
///
/// # Errors
/// `input`.
pub fn intent_digest(envelope: &[u8]) -> Result<Vec<u8>, Error> {
    let envelope: IntentEnvelope = decode(envelope)?;
    let d = intent::intent_digest(&envelope).map_err(|_| Error::Input)?;
    encode(&d.to_value())
}

/// Verifies a tagged `COSE_Sign1` against a `key-set` and returns `{kid, payload}` (CR-55).
///
/// # Errors
/// `input` or a COSE name.
pub fn verify_cose_sign1(
    sign1: &[u8],
    key_set: &[u8],
    content_type: &str,
) -> Result<Vec<u8>, Error> {
    let keys: KeySet = decode(key_set)?;
    let v = cose::verify_sign1(&PureBackend, sign1, &keys, content_type).map_err(Error::Cose)?;
    encode(&map([
        ("kid", Some(Value::Bytes(v.kid.to_vec()))),
        ("payload", Some(Value::Bytes(v.payload))),
    ]))
}

/// Verifies binding-signed Domain Metadata against the trusted binding `key-set` and returns
/// the `domain-metadata` (CR-58).
///
/// # Errors
/// `input` or a key-scope name.
pub fn verify_metadata(signed: &[u8], trusted: &[u8]) -> Result<Vec<u8>, Error> {
    let trusted: KeySet = decode(trusted)?;
    let metadata =
        key_scope::verify_metadata(&PureBackend, signed, &trusted).map_err(Error::KeyScope)?;
    metadata.to_bytes().map_err(|_| Error::Input)
}

/// Resolves the `operational-key` that signed an artefact of `domain` (a `digest`) at `iat`
/// for `usage` (a `key-usage`) (CR-58 m.5).
///
/// # Errors
/// `input` or a key-scope name.
pub fn operational_key(
    metadata: &[u8],
    domain: &[u8],
    excerpt: &[u8],
    usage: &str,
    iat: TrustedTime,
) -> Result<Vec<u8>, Error> {
    // L0-SIG-62a, OP-126 m.5
    let metadata = DomainMetadata::from_bytes(metadata)
        .map_err(|e| Error::KeyScope(KeyScopeError::Payload(e)))?;
    let domain: Digest = decode(domain)?;
    let usage = word(&Value::text(usage), &USAGES).map_err(|_| Error::Input)?;
    let key = key_scope::operational_key(&PureBackend, &metadata, &domain, excerpt, usage, iat)
        .map_err(Error::KeyScope)?;
    key.to_bytes().map_err(|_| Error::Input)
}

/// Verifies an Access-native compact JWS and its claims and returns the payload JSON text
/// (CR-55 m.8, m.9, CR-56).
///
/// # Errors
/// `input`, a JWS name or a claim name.
pub fn verify_jws_compact(
    token: &str,
    key_set: &[u8],
    typ: &str,
    issuer: &str,
    audience: &str,
    now: TrustedTime,
    skew_ms: u64,
) -> Result<String, Error> {
    let keys: KeySet = decode(key_set)?;
    let v =
        jws::verify_compact(&PureBackend, token, &keys, typ, Origin::Native).map_err(Error::Jws)?;
    let rules = ClaimRules {
        issuer,
        audience,
        now,
        skew_ms,
    };
    jws::check_claims(&v.payload, &rules).map_err(Error::Claim)?;
    String::from_utf8(v.payload).map_err(|_| Error::Input)
}

/// Verifies an Access-native SD-JWT presentation and returns the disclosed claims as JSON text
/// (RFC 9901, CR-55 m.7).
///
/// # Errors
/// `input` or an SD-JWT name.
pub fn verify_sd_jwt(
    presentation: &str,
    key_set: &[u8],
    typ: &str,
    audience: &str,
    nonce: &str,
    now: TrustedTime,
    skew_ms: u64,
) -> Result<String, Error> {
    let keys: KeySet = decode(key_set)?;
    let rules = sd_jwt::Rules {
        typ,
        audience,
        nonce,
        now,
        skew_ms,
    };
    let v = sd_jwt::verify(&PureBackend, presentation, &keys, &rules, Origin::Native)
        .map_err(Error::SdJwt)?;
    let mut out = String::new();
    json_text(&v.claims, &mut out);
    Ok(out)
}

/// Checks a `validity-contract` at the moment of use (§9.12). `iat` is the carrying artefact's
/// signing time and `horizon_cap_ms` the effective horizon ceiling (OP-118 m.4).
///
/// # Errors
/// `input` or a validity name.
#[allow(clippy::too_many_arguments, reason = "OP-116 m.9")]
pub fn check_validity(
    contract: &[u8],
    now: TrustedTime,
    audience: &str,
    understood: Vec<String>,
    last_refresh: Option<TrustedTime>,
    online: bool,
    skew_ms: u64,
    iat: TrustedTime,
    horizon_cap_ms: u64,
) -> Result<(), Error> {
    let contract: ValidityContract = decode(contract)?;
    let understood: BTreeSet<String> = understood.into_iter().collect();
    let ctx = VerifierContext {
        now,
        audience,
        understood: &understood,
        last_refresh,
        online,
        skew_ms,
        iat,
        horizon_cap_ms,
    };
    validity::check(&contract, &ctx).map_err(Error::Validity)
}

/// RFC 9162 inclusion proof. `leaf_hash` and `root` are 32 bytes; `path` is the proof hashes
/// concatenated.
///
/// # Errors
/// `input` when a hash has the wrong length.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf_hash: &[u8],
    path: &[u8],
    root: &[u8],
) -> Result<bool, Error> {
    let (leaf, path, root) = (hash(leaf_hash)?, hashes(path)?, hash(root)?);
    Ok(digest::verify_inclusion(index, size, &leaf, &path, &root).is_ok())
}

/// RFC 9162 consistency proof. Roots are 32 bytes; `path` is the proof hashes concatenated.
///
/// # Errors
/// `input` when a hash has the wrong length.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &[u8],
    second_root: &[u8],
    path: &[u8],
) -> Result<bool, Error> {
    let (a, b, path) = (hash(first_root)?, hash(second_root)?, hashes(path)?);
    Ok(digest::verify_consistency(first, second, &a, &b, &path).is_ok())
}

fn json_text(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Str(s) => json_string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_text(item, out);
            }
            out.push(']');
        }
        Json::Object(members) => {
            out.push('{');
            for (i, (k, item)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_string(k, out);
                out.push(':');
                json_text(item, out);
            }
            out.push('}');
        }
    }
}

fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests;
