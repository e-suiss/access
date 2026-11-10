//! Compact JWE of the identity plane (RFC 7516, RFC 7518; CR-4, OP-155 m.3 (k)): ID tokens,
//! userinfo answers and JARM responses encrypted to a client, and request objects a client
//! encrypted to the realm. Key management is `ECDH-ES+A256KW` (primary) or `RSA-OAEP-256`
//! (per-client opt-in); content encryption is `A256GCM`. `RSA1_5` and every other algorithm
//! are refused, and the authority plane never uses JWE.

use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrap as _};
use aws_lc_rs::rand;
use aws_lc_rs::rsa::{
    OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
    PrivateDecryptingKey, PublicEncryptingKey,
};

/// Largest protected header read.
pub const MAX_HEADER: usize = 2048;

/// Largest compact JWE read or written.
pub const MAX_JWE: usize = 64 * 1024;

const CEK_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAPPED_LEN: usize = 40;

/// A key management algorithm (RFC 7518 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyAlg {
    /// ECDH-ES on P-256 with the derived key wrapping the content key (RFC 7518 §4.6).
    EcdhEsA256kw,
    /// RSAES-OAEP with SHA-256 and MGF1-SHA-256 (RFC 7518 §4.3); per-client opt-in.
    RsaOaep256,
}

impl KeyAlg {
    /// The JOSE `alg` value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EcdhEsA256kw => "ECDH-ES+A256KW",
            Self::RsaOaep256 => "RSA-OAEP-256",
        }
    }

    /// From the JOSE name; `RSA1_5` and anything else is `None` (CR-4).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ECDH-ES+A256KW" => Some(Self::EcdhEsA256kw),
            "RSA-OAEP-256" => Some(Self::RsaOaep256),
            _ => None,
        }
    }
}

/// The only content encryption algorithm (CR-4).
pub const ENC: &str = "A256GCM";

/// Why a JWE could not be made or opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JweError {
    /// Not a compact JWE within the size limits.
    #[error("format")]
    Format,
    /// The protected header is outside the profile.
    #[error("header")]
    Header,
    /// The key management or content algorithm is not allowed (CR-4).
    #[error("algorithm")]
    Algorithm,
    /// The key does not fit the algorithm, or is not a valid key.
    #[error("key")]
    Key,
    /// The content key or the content did not decrypt.
    #[error("decrypt")]
    Decrypt,
    /// No randomness, or the primitive failed.
    #[error("crypto")]
    Crypto,
}

impl JweError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Format => "jwe-format",
            Self::Header => "jwe-header",
            Self::Algorithm => "jwe-algorithm",
            Self::Key => "jwe-key",
            Self::Decrypt => "jwe-decrypt",
            Self::Crypto => "jwe-crypto",
        }
    }
}

/// A recipient's public encryption key, from its JWKS.
#[derive(Clone, PartialEq, Eq)]
pub enum RecipientKey {
    /// P-256, SEC1 uncompressed.
    P256(Vec<u8>),
    /// RSA modulus and exponent, big-endian.
    Rsa {
        /// Modulus.
        n: Vec<u8>,
        /// Exponent.
        e: Vec<u8>,
    },
}

impl core::fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::P256(_) => f.write_str("RecipientKey::P256"),
            Self::Rsa { .. } => f.write_str("RecipientKey::Rsa"),
        }
    }
}

impl RecipientKey {
    /// The key management algorithm this key serves.
    #[must_use]
    pub const fn alg(&self) -> KeyAlg {
        match self {
            Self::P256(_) => KeyAlg::EcdhEsA256kw,
            Self::Rsa { .. } => KeyAlg::RsaOaep256,
        }
    }
}

fn fill<const N: usize>() -> Result<[u8; N], JweError> {
    let mut out: [u8; N] = core::array::from_fn(|_| 0);
    rand::fill(&mut out).map_err(|_| JweError::Crypto)?;
    Ok(out)
}

fn be_len(n: usize) -> Result<[u8; 4], JweError> {
    u32::try_from(n)
        .map(u32::to_be_bytes)
        .map_err(|_| JweError::Format)
}

/// RFC 7518 §4.6.2: the Concat KDF of `ECDH-ES+A256KW` with empty `apu` and `apv`; one
/// SHA-256 round gives the 256-bit key encryption key.
fn concat_kdf(z: &[u8]) -> Result<[u8; 32], JweError> {
    let alg = KeyAlg::EcdhEsA256kw.name().as_bytes();
    let mut input = Vec::with_capacity(z.len().saturating_add(40));
    input.extend_from_slice(&1_u32.to_be_bytes());
    input.extend_from_slice(z);
    input.extend_from_slice(&be_len(alg.len())?);
    input.extend_from_slice(alg);
    input.extend_from_slice(&0_u32.to_be_bytes());
    input.extend_from_slice(&0_u32.to_be_bytes());
    input.extend_from_slice(&256_u32.to_be_bytes());
    digest(&SHA256, &input)
        .as_ref()
        .try_into()
        .map_err(|_| JweError::Crypto)
}

fn wrap(kek: &[u8; 32], cek: &[u8; CEK_LEN]) -> Result<Vec<u8>, JweError> {
    let kek = AesKek::new(&AES_256, kek).map_err(|_| JweError::Crypto)?;
    let mut out = vec![0; WRAPPED_LEN];
    let n = kek.wrap(cek, &mut out).map_err(|_| JweError::Crypto)?.len();
    out.truncate(n);
    Ok(out)
}

fn unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Result<[u8; CEK_LEN], JweError> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(JweError::Decrypt);
    }
    let kek = AesKek::new(&AES_256, kek).map_err(|_| JweError::Crypto)?;
    let mut out = [0; WRAPPED_LEN];
    let cek = kek
        .unwrap(wrapped, &mut out)
        .map_err(|_| JweError::Decrypt)?;
    cek.try_into().map_err(|_| JweError::Decrypt)
}

fn der_len(n: usize, out: &mut Vec<u8>) -> Result<(), JweError> {
    match n {
        0..=0x7f => out.push(u8::try_from(n).map_err(|_| JweError::Key)?),
        0x80..=0xff => {
            out.push(0x81);
            out.push(u8::try_from(n).map_err(|_| JweError::Key)?);
        }
        0x100..=0xffff => {
            out.push(0x82);
            out.extend_from_slice(&u16::try_from(n).map_err(|_| JweError::Key)?.to_be_bytes());
        }
        _ => return Err(JweError::Key),
    }
    Ok(())
}

fn der(tag: u8, body: &[u8], out: &mut Vec<u8>) -> Result<(), JweError> {
    out.push(tag);
    der_len(body.len(), out)?;
    out.extend_from_slice(body);
    Ok(())
}

fn der_uint(v: &[u8], out: &mut Vec<u8>) -> Result<(), JweError> {
    let start = v.iter().position(|b| *b != 0).ok_or(JweError::Key)?;
    let v = v.get(start..).ok_or(JweError::Key)?;
    let mut body = Vec::with_capacity(v.len().saturating_add(1));
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(v);
    der(0x02, &body, out)
}

/// `SubjectPublicKeyInfo` of an RSA key (RFC 8017 A.1.1, RFC 5280 §4.1.2.7).
fn rsa_spki(n: &[u8], e: &[u8]) -> Result<Vec<u8>, JweError> {
    const ALG: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut ints = Vec::with_capacity(n.len().saturating_add(16));
    der_uint(n, &mut ints)?;
    der_uint(e, &mut ints)?;
    let mut key = Vec::new();
    der(0x30, &ints, &mut key)?;
    let mut bits = vec![0];
    bits.extend_from_slice(&key);
    let mut body = ALG.to_vec();
    der(0x03, &bits, &mut body)?;
    let mut out = Vec::new();
    der(0x30, &body, &mut out)?;
    Ok(out)
}

fn header_text(
    alg: KeyAlg,
    epk: Option<&[u8]>,
    kid: Option<&str>,
    cty: Option<&str>,
) -> Result<String, JweError> {
    let mut h = format!(r#"{{"alg":"{}","enc":"{ENC}""#, alg.name());
    if let Some(sec1) = epk {
        let (x, y) = sec1
            .get(1..)
            .and_then(|xy| xy.split_at_checked(32))
            .ok_or(JweError::Crypto)?;
        h.push_str(r#","epk":{"kty":"EC","crv":"P-256","x":""#);
        h.push_str(&b64url_encode(x));
        h.push_str(r#"","y":""#);
        h.push_str(&b64url_encode(y));
        h.push_str(r#""}"#);
    }
    if let Some(k) = kid {
        h.push_str(r#","kid":""#);
        h.push_str(k);
        h.push('"');
    }
    if let Some(c) = cty {
        h.push_str(r#","cty":""#);
        h.push_str(c);
        h.push('"');
    }
    h.push('}');
    Ok(h)
}

fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+/".contains(&b))
}

/// Encrypts `plaintext` to `key` as a compact JWE with `A256GCM`; `kid` names the recipient's
/// key and `cty` the content type (`JWT` for a nested signed token).
///
/// # Errors
/// [`JweError`].
pub fn encrypt(
    key: &RecipientKey,
    kid: Option<&str>,
    cty: Option<&str>,
    plaintext: &[u8],
) -> Result<String, JweError> {
    if kid.is_some_and(|k| !token_ok(k)) || cty.is_some_and(|c| !token_ok(c)) {
        return Err(JweError::Header);
    }
    if plaintext.len() > MAX_JWE {
        return Err(JweError::Format);
    }
    let cek: [u8; CEK_LEN] = fill()?;
    let (header, encrypted_key) = match key {
        RecipientKey::P256(sec1) => {
            if sec1.len() != 65 || sec1.first() != Some(&4) {
                return Err(JweError::Key);
            }
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let eph =
                EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| JweError::Crypto)?;
            let epk = eph.compute_public_key().map_err(|_| JweError::Crypto)?;
            let kek = agreement::agree_ephemeral(
                eph,
                UnparsedPublicKey::new(&ECDH_P256, sec1.as_slice()),
                JweError::Key,
                concat_kdf,
            )?;
            (
                header_text(KeyAlg::EcdhEsA256kw, Some(epk.as_ref()), kid, cty)?,
                wrap(&kek, &cek)?,
            )
        }
        RecipientKey::Rsa { n, e } => {
            let public =
                PublicEncryptingKey::from_der(&rsa_spki(n, e)?).map_err(|_| JweError::Key)?;
            if public.key_size_bits() < 2048 {
                return Err(JweError::Key);
            }
            let oaep = OaepPublicEncryptingKey::new(public).map_err(|_| JweError::Key)?;
            let mut out = vec![0; oaep.ciphertext_size()];
            let n = oaep
                .encrypt(&OAEP_SHA256_MGF1SHA256, &cek, &mut out, None)
                .map_err(|_| JweError::Crypto)?
                .len();
            out.truncate(n);
            (header_text(KeyAlg::RsaOaep256, None, kid, cty)?, out)
        }
    };
    let protected = b64url_encode(header.as_bytes());
    let iv: [u8; NONCE_LEN] = fill()?;
    let sealing =
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &cek).map_err(|_| JweError::Crypto)?);
    let mut body = plaintext.to_vec();
    let tag = sealing
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(protected.as_bytes()),
            &mut body,
        )
        .map_err(|_| JweError::Crypto)?;
    let out = format!(
        "{protected}.{}.{}.{}.{}",
        b64url_encode(&encrypted_key),
        b64url_encode(&iv),
        b64url_encode(&body),
        b64url_encode(tag.as_ref())
    );
    if out.len() > MAX_JWE {
        return Err(JweError::Format);
    }
    Ok(out)
}

/// A private key that opens JWEs addressed to it.
pub enum DecryptKey {
    /// P-256, for `ECDH-ES+A256KW`.
    P256(agreement::PrivateKey),
    /// RSA, for `RSA-OAEP-256`.
    Rsa(OaepPrivateDecryptingKey),
}

impl core::fmt::Debug for DecryptKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DecryptKey([redacted])")
    }
}

impl DecryptKey {
    /// A P-256 key from PKCS#8 or RFC 5915 DER.
    ///
    /// # Errors
    /// [`JweError::Key`].
    pub fn p256(der: &[u8]) -> Result<Self, JweError> {
        agreement::PrivateKey::from_private_key_der(&ECDH_P256, der)
            .map(Self::P256)
            .map_err(|_| JweError::Key)
    }

    /// An RSA key of at least 2048 bits from PKCS#8 DER.
    ///
    /// # Errors
    /// [`JweError::Key`].
    pub fn rsa(pkcs8: &[u8]) -> Result<Self, JweError> {
        let key = PrivateDecryptingKey::from_pkcs8(pkcs8).map_err(|_| JweError::Key)?;
        if key.key_size_bits() < 2048 {
            return Err(JweError::Key);
        }
        OaepPrivateDecryptingKey::new(key)
            .map(Self::Rsa)
            .map_err(|_| JweError::Key)
    }

    /// The algorithm the key opens.
    #[must_use]
    pub const fn alg(&self) -> KeyAlg {
        match self {
            Self::P256(_) => KeyAlg::EcdhEsA256kw,
            Self::Rsa(_) => KeyAlg::RsaOaep256,
        }
    }
}

/// What a JWE's protected header said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The plaintext.
    pub plaintext: Vec<u8>,
    /// `kid`, when present.
    pub kid: Option<String>,
    /// `cty`, when present.
    pub cty: Option<String>,
}

fn coordinate(v: Option<&Json>) -> Result<Vec<u8>, JweError> {
    v.and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
        .filter(|b| b.len() == 32)
        .ok_or(JweError::Header)
}

/// Opens a compact JWE with `key`. The header may hold only `alg`, `enc`, `epk`, `kid`, `cty`
/// and `typ`: `zip`, `crit`, `jku`, `x5u` and the rest are refused; `alg` must be the key's own
/// algorithm and `enc` `A256GCM` (CR-4).
///
/// # Errors
/// [`JweError`].
pub fn decrypt(key: &DecryptKey, jwe: &str) -> Result<Opened, JweError> {
    if jwe.len() > MAX_JWE {
        return Err(JweError::Format);
    }
    let mut it = jwe.split('.');
    let (Some(head), Some(wrapped), Some(iv), Some(body), Some(tag), None) = (
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
    ) else {
        return Err(JweError::Format);
    };
    let decode = |part: &str| b64url_decode(part).map_err(|_| JweError::Format);
    let header = json::parse(&decode(head)?, MAX_HEADER).map_err(|_| JweError::Header)?;
    let Json::Object(members) = &header else {
        return Err(JweError::Header);
    };
    if members
        .iter()
        .any(|(n, _)| !matches!(n.as_str(), "alg" | "enc" | "epk" | "kid" | "cty" | "typ"))
    {
        return Err(JweError::Header);
    }
    let alg = header
        .get("alg")
        .and_then(Json::as_str)
        .and_then(KeyAlg::from_name)
        .ok_or(JweError::Algorithm)?;
    if alg != key.alg() || header.get("enc").and_then(Json::as_str) != Some(ENC) {
        return Err(JweError::Algorithm);
    }
    let encrypted_key = decode(wrapped)?;
    let cek = match key {
        DecryptKey::P256(private) => {
            let epk = header.get("epk").ok_or(JweError::Header)?;
            let Json::Object(epk_members) = epk else {
                return Err(JweError::Header);
            };
            if epk_members
                .iter()
                .any(|(n, _)| !matches!(n.as_str(), "kty" | "crv" | "x" | "y"))
                || epk.get("kty").and_then(Json::as_str) != Some("EC")
                || epk.get("crv").and_then(Json::as_str) != Some("P-256")
            {
                return Err(JweError::Header);
            }
            let mut sec1 = vec![4];
            sec1.extend(coordinate(epk.get("x"))?);
            sec1.extend(coordinate(epk.get("y"))?);
            let kek = agreement::agree(
                private,
                UnparsedPublicKey::new(&ECDH_P256, sec1.as_slice()),
                JweError::Key,
                concat_kdf,
            )?;
            unwrap(&kek, &encrypted_key)?
        }
        DecryptKey::Rsa(private) => {
            if header.get("epk").is_some() {
                return Err(JweError::Header);
            }
            let mut out = vec![0; private.min_output_size()];
            let cek = private
                .decrypt(&OAEP_SHA256_MGF1SHA256, &encrypted_key, &mut out, None)
                .map_err(|_| JweError::Decrypt)?;
            <[u8; CEK_LEN]>::try_from(&*cek).map_err(|_| JweError::Decrypt)?
        }
    };
    let iv: [u8; NONCE_LEN] = decode(iv)?.try_into().map_err(|_| JweError::Format)?;
    let mut body = decode(body)?;
    let tag = decode(tag)?;
    if tag.len() != TAG_LEN {
        return Err(JweError::Format);
    }
    body.extend_from_slice(&tag);
    let opening =
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &cek).map_err(|_| JweError::Crypto)?);
    let plaintext = opening
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(head.as_bytes()),
            &mut body,
        )
        .map_err(|_| JweError::Decrypt)?
        .to_vec();
    let text = |n: &str| header.get(n).and_then(Json::as_str).map(String::from);
    Ok(Opened {
        plaintext,
        kid: text("kid"),
        cty: text("cty"),
    })
}

#[cfg(test)]
mod tests;
