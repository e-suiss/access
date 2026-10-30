//! Envelope encryption (CR-32, T27, T39, OP-135): per-body DEKs wrapped by a domain or realm
//! KEK. A body DEK encrypts one message and is consumed by it; a long-lived DEK counts its
//! messages and refuses past its limit (V4).

use std::collections::BTreeMap;

use aws_lc_rs::aead::{
    AES_256_GCM, AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey,
};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::dit::DitGuard;
use crate::secret::Secret;

/// Prefix of every additional-data input, so ciphertexts cannot move between uses (OP-135).
/// The caller's context follows it.
pub const AAD_CONTEXT: &[u8] = b"access/aead/v1\0";

/// Most messages one long-lived DEK encrypts (OP-135 m.3).
pub const MESSAGE_LIMIT: u64 = 1 << 32;

/// Why an envelope operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The random source failed.
    #[error("random source")]
    Random,
    /// Wrapping or unwrapping failed: wrong KEK or corrupt wrapped key.
    #[error("key wrap")]
    Wrap,
    /// Decryption failed: wrong key, data or context.
    #[error("decrypt")]
    Open,
    /// Encryption failed.
    #[error("encrypt")]
    Seal,
    /// The DEK reached its message limit or its counter would overflow (V4): rotate it.
    #[error("data key exhausted")]
    Exhausted,
}

impl EnvelopeError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Random => "envelope-random",
            Self::Wrap => "envelope-wrap",
            Self::Open => "envelope-open",
            Self::Seal => "envelope-seal",
            Self::Exhausted => "envelope-exhausted",
        }
    }
}

/// A data encryption key.
pub struct Dek(Secret<[u8; 32]>);

impl Dek {
    /// A fresh key from the system random source.
    ///
    /// # Errors
    /// [`EnvelopeError::Random`].
    pub fn generate() -> Result<Self, EnvelopeError> {
        let mut k = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut k)
            .map_err(|_| EnvelopeError::Random)?;
        let dek = Self(Secret::new(k));
        zeroize::Zeroize::zeroize(&mut k);
        Ok(dek)
    }

    /// A key from its bytes, for a KEK adapter that unwrapped it.
    #[must_use]
    pub fn from_secret(key: Secret<[u8; 32]>) -> Self {
        Self(key)
    }

    /// The key bytes, for a KEK adapter that wraps it.
    #[must_use]
    pub fn secret(&self) -> &Secret<[u8; 32]> {
        &self.0
    }

    fn key(&self, alg: &'static aws_lc_rs::aead::Algorithm) -> Result<LessSafeKey, EnvelopeError> {
        Ok(LessSafeKey::new(
            UnboundKey::new(alg, self.0.expose()).map_err(|_| EnvelopeError::Seal)?,
        ))
    }
}

/// A key encryption key held behind a port; the PKCS#11 adapter replaces the in-process one
/// (OP-94, OP-135 m.4).
pub trait Kek {
    /// Identifies this KEK version, stored next to every key it wraps.
    fn id(&self) -> &str;
    /// Wraps a DEK.
    ///
    /// # Errors
    /// [`EnvelopeError::Wrap`].
    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError>;
    /// Unwraps a DEK this KEK wrapped.
    ///
    /// # Errors
    /// [`EnvelopeError::Wrap`].
    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError>;
}

/// An in-process KEK under AES-256 Key Wrap (RFC 3394); tests only, an HSM keeps real ones.
#[cfg(any(test, feature = "testing"))]
pub struct SoftKek {
    id: String,
    key: Secret<[u8; 32]>,
}

#[cfg(any(test, feature = "testing"))]
impl SoftKek {
    /// A KEK named `id`.
    #[must_use]
    pub fn new(id: &str, key: [u8; 32]) -> Self {
        Self {
            id: id.to_owned(),
            key: Secret::new(key),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrap};

#[cfg(any(test, feature = "testing"))]
impl Kek for SoftKek {
    fn id(&self) -> &str {
        &self.id
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError> {
        // CR-39 m.6
        let _dit = DitGuard::new();
        let kek = AesKek::new(&AES_256, self.key.expose()).map_err(|_| EnvelopeError::Wrap)?;
        let mut out = vec![0; 40];
        let n = kek
            .wrap(dek.0.expose(), &mut out)
            .map_err(|_| EnvelopeError::Wrap)?
            .len();
        out.truncate(n);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError> {
        // CR-39 m.6
        let _dit = DitGuard::new();
        let kek = AesKek::new(&AES_256, self.key.expose()).map_err(|_| EnvelopeError::Wrap)?;
        let mut out = Zeroizing::new([0_u8; 40]);
        let plain = kek
            .unwrap(wrapped, out.as_mut_slice())
            .map_err(|_| EnvelopeError::Wrap)?;
        let key: [u8; 32] = plain
            .get(..32)
            .and_then(|k| k.try_into().ok())
            .ok_or(EnvelopeError::Wrap)?;
        if plain.len() != 32 {
            return Err(EnvelopeError::Wrap);
        }
        Ok(Dek(Secret::new(key)))
    }
}

/// A ciphertext with its nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The 96-bit nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext and tag.
    pub ciphertext: Vec<u8>,
}

fn aad(context: &[u8]) -> Vec<u8> {
    let mut a = AAD_CONTEXT.to_vec();
    a.extend_from_slice(context);
    a
}

fn nonce() -> Result<[u8; NONCE_LEN], EnvelopeError> {
    let mut n = [0_u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut n)
        .map_err(|_| EnvelopeError::Random)?;
    Ok(n)
}

fn seal_with(key: &LessSafeKey, context: &[u8], plaintext: &[u8]) -> Result<Sealed, EnvelopeError> {
    // CR-39 m.6
    let _dit = DitGuard::new();
    let n = nonce()?;
    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(n),
        Aad::from(aad(context)),
        &mut buf,
    )
    .map_err(|_| EnvelopeError::Seal)?;
    Ok(Sealed {
        nonce: n,
        ciphertext: buf,
    })
}

fn open_with(
    key: &LessSafeKey,
    context: &[u8],
    sealed: &Sealed,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    // CR-39 m.6
    let _dit = DitGuard::new();
    let mut buf = Zeroizing::new(sealed.ciphertext.clone());
    let len = key
        .open_in_place(
            Nonce::assume_unique_for_key(sealed.nonce),
            Aad::from(aad(context)),
            buf.as_mut_slice(),
        )
        .map_err(|_| EnvelopeError::Open)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

/// Encrypts one body under its own DEK, which the call consumes (T39): a body key never
/// encrypts a second message. `context` binds the ciphertext to its use (domain, body digest).
///
/// # Errors
/// [`EnvelopeError`].
pub fn seal_body(dek: Dek, context: &[u8], plaintext: &[u8]) -> Result<Sealed, EnvelopeError> {
    let key = dek.key(&AES_256_GCM)?;
    drop(dek);
    seal_with(&key, context, plaintext)
}

/// Decrypts a body.
///
/// # Errors
/// [`EnvelopeError::Open`] for a wrong key, context or a modified ciphertext.
pub fn open_body(
    dek: &Dek,
    context: &[u8],
    sealed: &Sealed,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    open_with(&dek.key(&AES_256_GCM)?, context, sealed)
}

/// A long-lived DEK (per subject and retention class, OP-74) under AES-256-GCM-SIV, counting
/// its messages (OP-135 m.3).
pub struct Sealer {
    dek: Dek,
    used: u64,
    limit: u64,
}

impl Sealer {
    /// A sealer that has already encrypted `used` messages.
    #[must_use]
    pub const fn new(dek: Dek, used: u64) -> Self {
        Self {
            dek,
            used,
            limit: MESSAGE_LIMIT,
        }
    }

    #[cfg(test)]
    const fn with_limit(dek: Dek, used: u64, limit: u64) -> Self {
        Self { dek, used, limit }
    }

    /// Messages encrypted so far.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Encrypts one message.
    ///
    /// # Errors
    /// [`EnvelopeError::Exhausted`] at the limit (V4); [`EnvelopeError`] otherwise.
    pub fn seal(&mut self, context: &[u8], plaintext: &[u8]) -> Result<Sealed, EnvelopeError> {
        let next = self.used.checked_add(1).ok_or(EnvelopeError::Exhausted)?;
        if next > self.limit {
            return Err(EnvelopeError::Exhausted);
        }
        let sealed = seal_with(&self.dek.key(&AES_256_GCM_SIV)?, context, plaintext)?;
        self.used = next;
        Ok(sealed)
    }

    /// Decrypts a message of this DEK.
    ///
    /// # Errors
    /// [`EnvelopeError::Open`].
    pub fn open(
        &self,
        context: &[u8],
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        open_with(&self.dek.key(&AES_256_GCM_SIV)?, context, sealed)
    }
}

/// Unwrapped DEKs held briefly (CR-32.2, OP-135 m.5): by wrapped key, until `ttl` after
/// unwrapping, at most `max` at once. Dropped keys are zeroized.
pub struct DekCache {
    ttl_ms: u64,
    max: usize,
    entries: BTreeMap<Vec<u8>, (Dek, u64)>,
}

/// Default lifetime of a cached DEK (PD).
pub const CACHE_TTL_MS: u64 = 5 * 60 * 1000;

/// Default size of the cache (PD).
pub const CACHE_MAX: usize = 10_000;

impl Default for DekCache {
    fn default() -> Self {
        Self::new(CACHE_TTL_MS, CACHE_MAX)
    }
}

impl DekCache {
    /// A cache with the given lifetime and size.
    #[must_use]
    pub const fn new(ttl_ms: u64, max: usize) -> Self {
        Self {
            ttl_ms,
            max,
            entries: BTreeMap::new(),
        }
    }

    /// The DEK wrapped as `wrapped` at time `now_ms`, unwrapping it with `kek` on a miss or after
    /// expiry. Expired entries are dropped.
    ///
    /// # Errors
    /// [`EnvelopeError::Wrap`].
    pub fn get(
        &mut self,
        kek: &dyn Kek,
        wrapped: &[u8],
        now_ms: u64,
    ) -> Result<&Dek, EnvelopeError> {
        self.entries.retain(|_, (_, expires)| *expires > now_ms);
        if !self.entries.contains_key(wrapped) {
            if self.entries.len() >= self.max {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, e))| *e)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    self.entries.remove(&k);
                }
            }
            let dek = kek.unwrap(wrapped)?;
            self.entries
                .insert(wrapped.to_vec(), (dek, now_ms.saturating_add(self.ttl_ms)));
        }
        self.entries
            .get(wrapped)
            .map(|(d, _)| d)
            .ok_or(EnvelopeError::Wrap)
    }

    /// Drops a DEK at once, as crypto-shredding of its body requires.
    pub fn forget(&mut self, wrapped: &[u8]) {
        self.entries.remove(wrapped);
    }

    /// Cached keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Re-wraps a DEK from one KEK version to another (rotation, §17.10.4).
///
/// # Errors
/// [`EnvelopeError::Wrap`].
pub fn rewrap(from: &dyn Kek, to: &dyn Kek, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    to.wrap(&from.unwrap(wrapped)?)
}

#[cfg(test)]
mod tests;
