//! The data-defined pre-hash and pepper of an imported hash (TN-85): what the source identity provider did to
//! the password before its hash function, so bcrypt over SHA-256 or a peppered hash imports
//! without code.

use core::fmt;

use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use super::LegacyHashError;
use super::b64;
use super::crypt::Digest;
use crate::secret::Secret;

/// A digest applied to the (peppered) password before the stored hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Prehash {
    /// The password as is.
    #[default]
    None,
    /// Lower-case hex of MD5.
    Md5Hex,
    /// Lower-case hex of SHA-1.
    Sha1Hex,
    /// Lower-case hex of SHA-256.
    Sha256Hex,
    /// The 32 raw bytes of SHA-256.
    Sha256Raw,
    /// Lower-case hex of SHA-512.
    Sha512Hex,
    /// Standard padded base64 of SHA-256.
    Sha256Base64,
}

impl Prehash {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "md5-hex" => Self::Md5Hex,
            "sha1-hex" => Self::Sha1Hex,
            "sha256-hex" => Self::Sha256Hex,
            "sha256-raw" => Self::Sha256Raw,
            "sha512-hex" => Self::Sha512Hex,
            "sha256-base64" => Self::Sha256Base64,
            _ => return None,
        })
    }

    /// The stable spelling in a transform spec.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Md5Hex => "md5-hex",
            Self::Sha1Hex => "sha1-hex",
            Self::Sha256Hex => "sha256-hex",
            Self::Sha256Raw => "sha256-raw",
            Self::Sha512Hex => "sha512-hex",
            Self::Sha256Base64 => "sha256-base64",
        }
    }
}

/// A pepper the source identity provider mixed in; the material never prints.
pub enum Pepper {
    /// Bytes put before the password.
    Prefix(Secret<Vec<u8>>),
    /// Bytes put after the password.
    Suffix(Secret<Vec<u8>>),
    /// HMAC-SHA-256 of the password under this key, as lower-case hex.
    HmacSha256(Secret<Vec<u8>>),
}

impl Pepper {
    /// The stable kind name in a transform spec.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Prefix(_) => "prefix",
            Self::Suffix(_) => "suffix",
            Self::HmacSha256(_) => "hmac-sha256",
        }
    }
}

impl fmt::Debug for Pepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pepper::{}(..)", self.kind())
    }
}

/// Pepper first, then pre-hash, then the stored hash function.
#[derive(Debug, Default)]
pub struct Transform {
    /// The pre-hash.
    pub prehash: Prehash,
    /// The pepper.
    pub pepper: Option<Pepper>,
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(H.get(usize::from(b >> 4)).copied().unwrap_or(b'0'));
        out.push(H.get(usize::from(b & 15)).copied().unwrap_or(b'0'));
    }
    out
}

fn base64_std(bytes: &[u8]) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity((bytes.len().saturating_add(2) / 3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let w = b(0).wrapping_shl(16) | b(1).wrapping_shl(8) | b(2);
        for k in 0..4u32 {
            let shift = 18u32.wrapping_sub(k.wrapping_mul(6));
            let i = usize::try_from(w.wrapping_shr(shift) & 0x3f).unwrap_or(0);
            let real = usize::try_from(k).unwrap_or(0) <= chunk.len();
            out.push(if real {
                A.get(i).copied().unwrap_or(b'A')
            } else {
                b'='
            });
        }
    }
    out
}

impl Transform {
    /// No pepper, no pre-hash.
    #[must_use]
    pub fn identity() -> Self {
        Self::default()
    }

    /// Parses `"pepper=<kind>:<base64>;prehash=<name>"`; either part may be left out and the
    /// empty string is the identity. Kinds: `prefix`, `suffix`, `hmac-sha256`.
    ///
    /// # Errors
    /// [`LegacyHashError::Transform`].
    pub fn parse(spec: &str) -> Result<Self, LegacyHashError> {
        let mut out = Self::default();
        let (mut seen_pepper, mut seen_prehash) = (false, false);
        for part in spec.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (key, value) = part.split_once('=').ok_or(LegacyHashError::Transform)?;
            match key.trim() {
                "prehash" if !seen_prehash => {
                    seen_prehash = true;
                    out.prehash = Prehash::parse(value.trim()).ok_or(LegacyHashError::Transform)?;
                }
                "pepper" if !seen_pepper => {
                    seen_pepper = true;
                    let (kind, material) =
                        value.split_once(':').ok_or(LegacyHashError::Transform)?;
                    let bytes = Secret::new(
                        b64::decode(material.trim()).ok_or(LegacyHashError::Transform)?,
                    );
                    if bytes.expose().is_empty() {
                        return Err(LegacyHashError::Transform);
                    }
                    out.pepper = Some(match kind.trim() {
                        "prefix" => Pepper::Prefix(bytes),
                        "suffix" => Pepper::Suffix(bytes),
                        "hmac-sha256" => Pepper::HmacSha256(bytes),
                        _ => return Err(LegacyHashError::Transform),
                    });
                }
                _ => return Err(LegacyHashError::Transform),
            }
        }
        Ok(out)
    }

    /// The bytes the stored hash function takes for `password`.
    pub(super) fn apply(&self, password: &[u8]) -> Zeroizing<Vec<u8>> {
        let peppered: Zeroizing<Vec<u8>> = Zeroizing::new(match &self.pepper {
            None => password.to_vec(),
            Some(Pepper::Prefix(p)) => [p.expose().as_slice(), password].concat(),
            Some(Pepper::Suffix(p)) => [password, p.expose().as_slice()].concat(),
            Some(Pepper::HmacSha256(k)) => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, k.expose());
                hex(hmac::sign(&key, password).as_ref())
            }
        });
        let d = |alg: Digest| alg.of(&[&peppered]);
        Zeroizing::new(match self.prehash {
            Prehash::None => return peppered,
            Prehash::Md5Hex => hex(&d(Digest::Md5)),
            Prehash::Sha1Hex => hex(&d(Digest::Sha1)),
            Prehash::Sha256Hex => hex(&d(Digest::Sha256)),
            Prehash::Sha256Raw => d(Digest::Sha256).to_vec(),
            Prehash::Sha512Hex => hex(&d(Digest::Sha512)),
            Prehash::Sha256Base64 => base64_std(&d(Digest::Sha256)),
        })
    }
}
