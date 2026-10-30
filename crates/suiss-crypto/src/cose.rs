//! `COSE_Sign1` verification profile (CR-55 m.4, m.6, CR-7, OP-140 m.2).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::dcbor::{self, Limits, TagAllowlist, Value};
use crate::sig::{Backend, SignatureError, ed25519, p256};

/// Signature algorithms this profile knows (IANA COSE, RFC 9864).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    /// Ed25519, −19.
    Ed25519,
    /// ESP256, −9.
    Esp256,
    /// ES256, −7 (verify only, MD-3).
    Es256,
    /// ML-DSA-44, −48; modelled, off by default (CR-55 m.1).
    MlDsa44,
    /// ML-DSA-65, −49; modelled, off by default.
    MlDsa65,
    /// ML-DSA-87, −50; modelled, off by default.
    MlDsa87,
}

impl Algorithm {
    /// The COSE identifier.
    #[must_use]
    pub const fn cose(self) -> i64 {
        match self {
            Self::Ed25519 => -19,
            Self::Esp256 => -9,
            Self::Es256 => -7,
            Self::MlDsa44 => -48,
            Self::MlDsa65 => -49,
            Self::MlDsa87 => -50,
        }
    }

    /// Whether it can be verified; ML-DSA has no provider yet (CR-55 m.1).
    #[must_use]
    pub const fn enabled(self) -> bool {
        matches!(self, Self::Ed25519 | Self::Esp256 | Self::Es256)
    }

    /// The algorithm with this COSE identifier.
    #[must_use]
    pub fn from_cose(id: i64) -> Option<Self> {
        [
            Self::Ed25519,
            Self::Esp256,
            Self::Es256,
            Self::MlDsa44,
            Self::MlDsa65,
            Self::MlDsa87,
        ]
        .into_iter()
        .find(|a| a.cose() == id)
    }
}

/// A verification key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519 public key.
    Ed25519([u8; 32]),
    /// P-256 public key, SEC1 encoding.
    P256(Vec<u8>),
    /// `AKP` ML-DSA public key (RFC 9964); modelled from day one, off by default.
    MlDsa(Algorithm, Vec<u8>),
}

impl PublicKey {
    /// Rejects keys that are not canonical points on the curve, or of small order (CR-56 row 11).
    ///
    /// # Errors
    /// [`SignatureError::NonCanonicalKey`] or [`SignatureError::SmallOrderKey`].
    pub fn check(&self) -> Result<(), SignatureError> {
        match self {
            Self::Ed25519(pk) => {
                let point = curve25519_dalek::edwards::CompressedEdwardsY(*pk)
                    .decompress()
                    .filter(|p| p.compress().as_bytes() == pk)
                    .ok_or(SignatureError::NonCanonicalKey)?;
                if point.is_small_order() {
                    Err(SignatureError::SmallOrderKey)
                } else {
                    Ok(())
                }
            }
            Self::P256(sec1) => {
                if sec1.len() != 65 || sec1.first() != Some(&0x04) {
                    return Err(SignatureError::NonCanonicalKey);
                }
                p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
                    .map(|_| ())
                    .map_err(|_| SignatureError::NonCanonicalKey)
            }
            Self::MlDsa(alg, key) => {
                let expected = match alg {
                    Algorithm::MlDsa44 => 1312,
                    Algorithm::MlDsa65 => 1952,
                    Algorithm::MlDsa87 => 2592,
                    _ => return Err(SignatureError::NonCanonicalKey),
                };
                if key.len() == expected {
                    Ok(())
                } else {
                    Err(SignatureError::Length)
                }
            }
        }
    }

    fn fits(&self, alg: Algorithm) -> bool {
        matches!(
            (self, alg),
            (Self::Ed25519(_), Algorithm::Ed25519)
                | (Self::P256(_), Algorithm::Esp256 | Algorithm::Es256)
        ) || matches!(self, Self::MlDsa(a, _) if *a == alg)
    }
}

/// Keys by `kid` (the raw 32-byte thumbprint, CR-55 m.4) and the algorithms metadata allows (CR-7).
#[derive(Clone, Debug, Default)]
pub struct KeySet {
    /// Keys by `kid`.
    pub keys: BTreeMap<[u8; 32], PublicKey>,
    /// Allowed algorithms, from client / Domain / Realm metadata only.
    pub allowed: BTreeSet<Algorithm>,
}

impl KeySet {
    /// Adds a key after [`PublicKey::check`].
    ///
    /// # Errors
    /// The key is rejected.
    pub fn insert(&mut self, kid: [u8; 32], key: PublicKey) -> Result<(), SignatureError> {
        key.check()?;
        self.keys.insert(kid, key);
        Ok(())
    }
}

/// A verified `COSE_Sign1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Algorithm used.
    pub algorithm: Algorithm,
    /// Key identifier.
    pub kid: [u8; 32],
    /// Payload bytes.
    pub payload: Vec<u8>,
}

/// Why a `COSE_Sign1` is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CoseError {
    /// Not canonical CBOR, missing tag 18, or a nested tag.
    #[error("not a canonical tagged COSE_Sign1: {0}")]
    Cbor(#[from] dcbor::DecodeError),
    /// Wrong structure.
    #[error("not a COSE_Sign1 structure")]
    Shape,
    /// Missing, duplicate or unknown protected header parameter.
    #[error("protected header not in profile")]
    Header,
    /// `crit` is present.
    #[error("crit not understood")]
    Crit,
    /// Unprotected header is not empty.
    #[error("unprotected header must be empty")]
    Unprotected,
    /// Algorithm not allowed by metadata, or unknown.
    #[error("algorithm not allowed")]
    Algorithm,
    /// No key with this `kid`.
    #[error("unknown kid")]
    UnknownKid,
    /// Key type does not match the algorithm.
    #[error("key type does not match algorithm")]
    KeyType,
    /// Content type differs from the expected one.
    #[error("unexpected content type")]
    ContentType,
    /// The signature does not verify.
    #[error("signature: {0}")]
    Signature(#[from] SignatureError),
    /// The payload is detached where it must be attached, or the other way round.
    #[error("payload presence does not match")]
    Payload,
}

impl CoseError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Cbor(e) => e.code(),
            Self::Shape => "cose-shape",
            Self::Header => "cose-header",
            Self::Crit => "cose-crit",
            Self::Unprotected => "cose-unprotected",
            Self::Algorithm => "cose-algorithm",
            Self::UnknownKid => "cose-unknown-kid",
            Self::KeyType => "cose-key-type",
            Self::ContentType => "cose-content-type",
            Self::Signature(e) => e.code(),
            Self::Payload => "cose-payload",
        }
    }
}

/// Protected header label `alg`.
pub const ALG: u64 = 1;
/// Protected header label `crit`.
pub const CRIT: u64 = 2;
/// Protected header label `content type`.
pub const CONTENT_TYPE: u64 = 3;
/// Protected header label `kid`.
pub const KID: u64 = 4;

const NIL: u8 = 0xf6;
const NO_TAGS: TagAllowlist = TagAllowlist::none();

/// A parsed `COSE_Sign1` that keeps the received bytes of the protected header, payload and
/// signature (OP-140 m.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sign1 {
    /// The protected header as received.
    pub protected: Vec<u8>,
    /// The payload as received; `None` when detached (`nil`, RFC 9052 §2).
    pub payload: Option<Vec<u8>>,
    /// The signature.
    pub signature: Vec<u8>,
}

fn bytes_item(input: &[u8], at: &mut usize) -> Result<Vec<u8>, CoseError> {
    let rest = input.get(*at..).ok_or(CoseError::Shape)?;
    let (v, used) = dcbor::decode_prefix(rest, Limits::CEILING, &NO_TAGS)?;
    *at = at.checked_add(used).ok_or(CoseError::Shape)?;
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(CoseError::Shape),
    }
}

/// Parses a tagged `COSE_Sign1` without verifying it. The unprotected header must be empty.
///
/// # Errors
/// [`CoseError`].
pub fn parse_sign1(bytes: &[u8]) -> Result<Sign1, CoseError> {
    match bytes {
        [0xd2, 0x84, ..] => {}
        [0xd2, ..] => return Err(CoseError::Shape),
        _ => return Err(CoseError::Cbor(dcbor::DecodeError::Tag)),
    }
    let mut at = 2;
    let protected = bytes_item(bytes, &mut at)?;
    let rest = bytes.get(at..).ok_or(CoseError::Shape)?;
    let (unprotected, used) = dcbor::decode_prefix(rest, Limits::CEILING, &NO_TAGS)?;
    at = at.checked_add(used).ok_or(CoseError::Shape)?;
    if unprotected != Value::Map(Vec::new()) {
        return Err(CoseError::Unprotected);
    }
    let payload = if bytes.get(at) == Some(&NIL) {
        at = at.checked_add(1).ok_or(CoseError::Shape)?;
        None
    } else {
        Some(bytes_item(bytes, &mut at)?)
    };
    let signature = bytes_item(bytes, &mut at)?;
    if at != bytes.len() {
        return Err(CoseError::Cbor(dcbor::DecodeError::TrailingBytes));
    }
    Ok(Sign1 {
        protected,
        payload,
        signature,
    })
}

struct Protected {
    alg: Algorithm,
    kid: [u8; 32],
    content_type: alloc::string::String,
}

fn protected(bytes: &[u8]) -> Result<Protected, CoseError> {
    let Value::Map(entries) = dcbor::decode(bytes, Limits::CEILING)? else {
        return Err(CoseError::Header);
    };
    let (mut alg, mut kid, mut ct) = (None, None, None);
    for (k, v) in &entries {
        match (k, v) {
            (Value::Unsigned(CRIT), _) => return Err(CoseError::Crit),
            (Value::Unsigned(ALG), v) => {
                alg = Some(
                    v.as_i64()
                        .and_then(Algorithm::from_cose)
                        .ok_or(CoseError::Algorithm)?,
                );
            }
            (Value::Unsigned(KID), Value::Bytes(b)) => {
                kid = Some(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| CoseError::Header)?);
            }
            (Value::Unsigned(CONTENT_TYPE), Value::Text(t)) => ct = Some(t.clone()),
            _ => return Err(CoseError::Header),
        }
    }
    Ok(Protected {
        alg: alg.ok_or(CoseError::Header)?,
        kid: kid.ok_or(CoseError::Header)?,
        content_type: ct.ok_or(CoseError::Header)?,
    })
}

/// The `Sig_structure` to be signed (RFC 9052 §4.4) with empty `external_aad`.
#[must_use]
pub fn to_be_signed(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let s = Value::Array(alloc::vec![
        Value::text("Signature1"),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    dcbor::encode(&s, Limits::CEILING).unwrap_or_default()
}

/// Verifies a tagged `COSE_Sign1` with an attached payload, signed by the producer itself:
/// high-S ECDSA is rejected (CR-9).
///
/// # Errors
/// [`CoseError`].
pub fn verify_sign1(
    backend: &impl Backend,
    bytes: &[u8],
    keys: &KeySet,
    content_type: &str,
) -> Result<Verified, CoseError> {
    verify_sign1_with(backend, bytes, None, keys, content_type, true)
}

/// [`verify_sign1`] for a `COSE_Sign1` whose payload is detached and given separately.
///
/// # Errors
/// [`CoseError`].
pub fn verify_sign1_detached(
    backend: &impl Backend,
    bytes: &[u8],
    payload: &[u8],
    keys: &KeySet,
    content_type: &str,
) -> Result<Verified, CoseError> {
    verify_sign1_with(backend, bytes, Some(payload), keys, content_type, true)
}

/// Verifies a tagged `COSE_Sign1`. `detached` is the payload when the message carries `nil`;
/// `native` rejects high-S ECDSA (own artefacts) and accepts it for external signers (CR-9).
/// The algorithm must be in `keys.allowed`, which comes from the caller's policy, never from
/// the header (CR-7).
///
/// # Errors
/// [`CoseError`].
pub fn verify_sign1_with(
    backend: &impl Backend,
    bytes: &[u8],
    detached: Option<&[u8]>,
    keys: &KeySet,
    content_type: &str,
    native: bool,
) -> Result<Verified, CoseError> {
    let msg = parse_sign1(bytes)?;
    let payload = match (&msg.payload, detached) {
        (Some(p), None) => p.as_slice(),
        (None, Some(p)) => p,
        _ => return Err(CoseError::Payload),
    };
    let h = protected(&msg.protected)?;
    if !keys.allowed.contains(&h.alg) || !h.alg.enabled() {
        return Err(CoseError::Algorithm);
    }
    if h.content_type != content_type {
        return Err(CoseError::ContentType);
    }
    let key = keys.keys.get(&h.kid).ok_or(CoseError::UnknownKid)?;
    if !key.fits(h.alg) {
        return Err(CoseError::KeyType);
    }
    let tbs = to_be_signed(&msg.protected, payload);
    match key {
        PublicKey::Ed25519(pk) => ed25519(backend, pk, &tbs, &msg.signature)?,
        PublicKey::P256(pk) => p256(backend, pk, &tbs, &msg.signature, native)?,
        PublicKey::MlDsa(..) => return Err(CoseError::Algorithm),
    }
    Ok(Verified {
        algorithm: h.alg,
        kid: h.kid,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests;
