//! RFC 9474 blind RSA as RFC 9578 token type `0x0002` uses it (RSABSSA-SHA384-PSS-Deterministic,
//! 2048-bit keys; OP-156 m.3 (z), E58): the issuer's raw private operation on a blinded message,
//! and the client's blinding and finalization. The raw RSA and big-number operations are
//! aws-lc's; the `rsa` crate is never used (CR-14). Identity plane only: authority artefacts are
//! never RSA (G46).

#![allow(
    unsafe_code,
    reason = "aws-lc's raw RSA and big-number calls (R-2); each block states its SAFETY"
)]

use core::ffi::c_long;
use core::ptr::{self, NonNull};

use aws_lc_rs::digest::{SHA384, digest};
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{RSA_PSS_2048_8192_SHA384, RsaPublicKeyComponents};
use aws_lc_sys as sys;
use zeroize::Zeroizing;

/// The modulus length in bytes (`Nk` of RFC 9578 §6).
pub const MODULUS_LEN: usize = 256;

/// The PSS salt length (RFC 9578 §6: 48).
pub const SALT_LEN: usize = 48;

const HASH_LEN: usize = 48;

const EXPONENT: [u8; 3] = [1, 0, 1];

/// Why a blind RSA operation did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BlindError {
    /// Not an RSA-2048 key with exponent 65537.
    #[error("key")]
    Key,
    /// A message or signature of the wrong length, or not below the modulus.
    #[error("input")]
    Input,
    /// The random source failed.
    #[error("random")]
    Random,
    /// The primitive failed, or its result did not check.
    #[error("operation")]
    Operation,
}

/// An issuer key: RSA-2048, used only for the raw private operation (`BlindSign`).
pub struct IssuerKey {
    rsa: NonNull<sys::RSA>,
    n: Vec<u8>,
}

// SAFETY: aws-lc RSA objects may be used from several threads at once for their non-mutating
// operations; after construction this type only signs and verifies, and frees once in `Drop`.
unsafe impl Send for IssuerKey {}
// SAFETY: as for `Send`.
unsafe impl Sync for IssuerKey {}

impl core::fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuerKey").finish_non_exhaustive()
    }
}

impl Drop for IssuerKey {
    fn drop(&mut self) {
        // SAFETY: `rsa` is the one reference this key owns.
        unsafe { sys::RSA_free(self.rsa.as_ptr()) }
    }
}

impl IssuerKey {
    /// A new key and its PKCS#8 form, which the caller seals before it is stored.
    ///
    /// # Errors
    /// [`BlindError`].
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>), BlindError> {
        let pair = KeyPair::generate(KeySize::Rsa2048).map_err(|_| BlindError::Operation)?;
        let der = Zeroizing::new(
            pair.as_der()
                .map_err(|_| BlindError::Key)?
                .as_ref()
                .to_vec(),
        );
        Ok((Self::from_pkcs8(&der)?, der))
    }

    /// The key a PKCS#8 form holds; anything but RSA-2048 with exponent 65537 is refused.
    ///
    /// # Errors
    /// [`BlindError::Key`].
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, BlindError> {
        let len = c_long::try_from(der.len()).map_err(|_| BlindError::Key)?;
        let mut p = der.as_ptr();
        // SAFETY: `p` points to `len` readable bytes; the call reads at most that many and
        // returns a new key or null.
        let pkey = unsafe { sys::d2i_AutoPrivateKey(ptr::null_mut(), &raw mut p, len) };
        let pkey = NonNull::new(pkey).ok_or(BlindError::Key)?;
        // SAFETY: `pkey` is ours; `get1` returns a new RSA reference or null, then ours is freed.
        let rsa = unsafe {
            let rsa = sys::EVP_PKEY_get1_RSA(pkey.as_ptr());
            sys::EVP_PKEY_free(pkey.as_ptr());
            rsa
        };
        let mut key = Self {
            rsa: NonNull::new(rsa).ok_or(BlindError::Key)?,
            n: Vec::new(),
        };
        // SAFETY: `key.rsa` is a valid RSA key; the getters borrow from it.
        let (checked, size, n, e) = unsafe {
            let r = key.rsa.as_ptr();
            (
                sys::RSA_check_key(r),
                sys::RSA_size(r),
                sys::RSA_get0_n(r),
                sys::RSA_get0_e(r),
            )
        };
        if checked != 1 || usize::try_from(size).ok() != Some(MODULUS_LEN) || e.is_null() {
            return Err(BlindError::Key);
        }
        key.n = padded::<MODULUS_LEN>(n)?.to_vec();
        if padded::<3>(e)? != EXPONENT {
            return Err(BlindError::Key);
        }
        Ok(key)
    }

    /// The modulus, big-endian, 256 bytes.
    #[must_use]
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// The public exponent, big-endian.
    #[must_use]
    pub const fn exponent(&self) -> &'static [u8] {
        &EXPONENT
    }

    /// The RFC 9578 §6.5 token key: the RSASSA-PSS `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn token_key(&self) -> Vec<u8> {
        token_key(&self.n).unwrap_or_default()
    }

    /// `BlindSign` (RFC 9474 §4.3): the raw private operation on `blinded`, checked against
    /// the public operation before it is returned.
    ///
    /// # Errors
    /// [`BlindError::Input`] for a message of the wrong length or not below the modulus;
    /// [`BlindError::Operation`].
    pub fn blind_sign(&self, blinded: &[u8]) -> Result<[u8; MODULUS_LEN], BlindError> {
        if blinded.len() != MODULUS_LEN || blinded >= self.n.as_slice() {
            return Err(BlindError::Input);
        }
        let mut sig = [0_u8; MODULUS_LEN];
        let mut check = Zeroizing::new([0_u8; MODULUS_LEN]);
        let (mut sig_len, mut check_len) = (0_usize, 0_usize);
        // SAFETY: `rsa` is valid; every buffer is `MODULUS_LEN` bytes and the lengths say so.
        let (signed, opened) = unsafe {
            let r = self.rsa.as_ptr();
            let signed = sys::RSA_sign_raw(
                r,
                &raw mut sig_len,
                sig.as_mut_ptr(),
                MODULUS_LEN,
                blinded.as_ptr(),
                MODULUS_LEN,
                sys::RSA_NO_PADDING,
            );
            let opened = sys::RSA_verify_raw(
                r,
                &raw mut check_len,
                check.as_mut_ptr(),
                MODULUS_LEN,
                sig.as_ptr(),
                MODULUS_LEN,
                sys::RSA_NO_PADDING,
            );
            (signed, opened)
        };
        if signed != 1
            || opened != 1
            || sig_len != MODULUS_LEN
            || check_len != MODULUS_LEN
            || check.as_slice() != blinded
        {
            return Err(BlindError::Operation);
        }
        Ok(sig)
    }
}

/// The RFC 9578 §6.5 token key of the modulus `n` (256 bytes) and exponent 65537.
#[must_use]
pub fn token_key(n: &[u8]) -> Option<Vec<u8>> {
    const ALG: [u8; 63] = [
        0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30,
        0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa2, 0x03,
        0x02, 0x01, 0x30,
    ];
    if n.len() != MODULUS_LEN || n.first().is_none_or(|b| b & 0x80 == 0) {
        return None;
    }
    let mut out = vec![0x30, 0x82, 0x01, 0x52];
    out.extend_from_slice(&ALG);
    out.extend_from_slice(&[
        0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
    ]);
    out.extend_from_slice(n);
    out.extend_from_slice(&[0x02, 0x03]);
    out.extend_from_slice(&EXPONENT);
    Some(out)
}

/// The modulus a [`token_key`] carries.
#[must_use]
pub fn token_key_modulus(key: &[u8]) -> Option<&[u8]> {
    let n = key.get(81..81 + MODULUS_LEN)?;
    (token_key(n).as_deref() == Some(key)).then_some(n)
}

/// The PKCS#1 `RSAPublicKey` inside a [`token_key`], as RSA-PSS verifiers take it.
#[must_use]
pub fn token_key_public(key: &[u8]) -> Option<&[u8]> {
    token_key_modulus(key)?;
    key.get(72..)
}

/// A blinded message and the inverse that finalizes its signature.
pub struct Blinded {
    /// `blinded_msg`, 256 bytes.
    pub message: [u8; MODULUS_LEN],
    inverse: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Blinded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blinded").finish_non_exhaustive()
    }
}

/// `Blind` (RFC 9474 §4.2) of `message` for the key with modulus `n` and exponent 65537:
/// EMSA-PSS with SHA-384 and a random 48-byte salt, then a random blinding factor.
///
/// # Errors
/// [`BlindError`].
pub fn blind(n: &[u8], message: &[u8]) -> Result<Blinded, BlindError> {
    if n.len() != MODULUS_LEN || n.first().is_none_or(|b| b & 0x80 == 0) {
        return Err(BlindError::Key);
    }
    let rng = SystemRandom::new();
    let mut salt = [0_u8; SALT_LEN];
    rng.fill(&mut salt).map_err(|_| BlindError::Random)?;
    let encoded = Zeroizing::new(pss_encode(message, &salt)?);
    let ctx = Ctx::new()?;
    let modulus = Bn::of(n)?;
    let exponent = Bn::of(&EXPONENT)?;
    let encoded = Bn::of(encoded.as_slice())?;
    let mut r_bytes = Zeroizing::new([0_u8; MODULUS_LEN]);
    for _ in 0..8 {
        rng.fill(r_bytes.as_mut_slice())
            .map_err(|_| BlindError::Random)?;
        if let Some(top) = r_bytes.first_mut() {
            *top &= 0x7f;
        }
        let factor = Bn::of(r_bytes.as_slice())?;
        let inverse = Bn::new()?;
        let masked = Bn::new()?;
        let out = Bn::new()?;
        // SAFETY: every pointer is a live big number or context owned above.
        let ok = unsafe {
            let c = ctx.0.as_ptr();
            !sys::BN_mod_inverse(inverse.ptr(), factor.ptr(), modulus.ptr(), c).is_null()
                && sys::BN_mod_exp(masked.ptr(), factor.ptr(), exponent.ptr(), modulus.ptr(), c)
                    == 1
                && sys::BN_mod_mul(out.ptr(), encoded.ptr(), masked.ptr(), modulus.ptr(), c) == 1
        };
        if ok {
            return Ok(Blinded {
                message: out.bytes()?,
                inverse: Zeroizing::new(inverse.bytes()?.to_vec()),
            });
        }
    }
    Err(BlindError::Operation)
}

/// `Finalize` (RFC 9474 §4.4): the signature over `message` from the issuer's `blind_sig`,
/// verified as a standard RSASSA-PSS SHA-384 signature before it is returned.
///
/// # Errors
/// [`BlindError`].
pub fn finalize(
    n: &[u8],
    message: &[u8],
    blinded: &Blinded,
    blind_sig: &[u8],
) -> Result<[u8; MODULUS_LEN], BlindError> {
    if n.len() != MODULUS_LEN || blind_sig.len() != MODULUS_LEN || blind_sig >= n {
        return Err(BlindError::Input);
    }
    let ctx = Ctx::new()?;
    let modulus = Bn::of(n)?;
    let z = Bn::of(blind_sig)?;
    let inverse = Bn::of(&blinded.inverse)?;
    let s = Bn::new()?;
    // SAFETY: every pointer is a live big number or context owned above.
    if unsafe {
        sys::BN_mod_mul(
            s.ptr(),
            z.ptr(),
            inverse.ptr(),
            modulus.ptr(),
            ctx.0.as_ptr(),
        )
    } != 1
    {
        return Err(BlindError::Operation);
    }
    let sig = s.bytes()?;
    RsaPublicKeyComponents { n, e: &EXPONENT }
        .verify(&RSA_PSS_2048_8192_SHA384, message, &sig)
        .map_err(|_| BlindError::Operation)?;
    Ok(sig)
}

const DB_LEN: usize = MODULUS_LEN - HASH_LEN - 1;
const ONE_AT: usize = DB_LEN - SALT_LEN - 1;
const PRIME_LEN: usize = 8 + HASH_LEN + SALT_LEN;

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-384, MGF1-SHA-384, `emBits` 2047.
fn pss_encode(message: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; MODULUS_LEN], BlindError> {
    let m_hash = digest(&SHA384, message);
    let mut prime = [0_u8; PRIME_LEN];
    prime
        .get_mut(8..PRIME_LEN - SALT_LEN)
        .ok_or(BlindError::Operation)?
        .copy_from_slice(m_hash.as_ref());
    prime
        .get_mut(PRIME_LEN - SALT_LEN..)
        .ok_or(BlindError::Operation)?
        .copy_from_slice(salt);
    let h = digest(&SHA384, &prime);
    let mut em = [0_u8; MODULUS_LEN];
    *em.get_mut(ONE_AT).ok_or(BlindError::Operation)? = 1;
    em.get_mut(ONE_AT + 1..DB_LEN)
        .ok_or(BlindError::Operation)?
        .copy_from_slice(salt);
    let mask = mgf1(h.as_ref())?;
    for (d, k) in em.iter_mut().zip(mask.iter()) {
        *d ^= k;
    }
    if let Some(top) = em.first_mut() {
        *top &= 0x7f;
    }
    em.get_mut(DB_LEN..MODULUS_LEN - 1)
        .ok_or(BlindError::Operation)?
        .copy_from_slice(h.as_ref());
    *em.last_mut().ok_or(BlindError::Operation)? = 0xbc;
    Ok(em)
}

/// MGF1 with SHA-384 (RFC 8017 §B.2.1), `DB_LEN` bytes.
fn mgf1(seed: &[u8]) -> Result<[u8; DB_LEN], BlindError> {
    let mut out = [0_u8; DB_LEN];
    for (counter, chunk) in (0_u32..).zip(out.chunks_mut(HASH_LEN)) {
        let mut block = [0_u8; HASH_LEN + 4];
        block
            .get_mut(..HASH_LEN)
            .ok_or(BlindError::Operation)?
            .copy_from_slice(seed);
        block
            .get_mut(HASH_LEN..)
            .ok_or(BlindError::Operation)?
            .copy_from_slice(&counter.to_be_bytes());
        let d = digest(&SHA384, &block);
        chunk.copy_from_slice(d.as_ref().get(..chunk.len()).ok_or(BlindError::Operation)?);
    }
    Ok(out)
}

fn padded<const N: usize>(bn: *const sys::BIGNUM) -> Result<[u8; N], BlindError> {
    if bn.is_null() {
        return Err(BlindError::Key);
    }
    let mut out = [0_u8; N];
    // SAFETY: `bn` is a live big number borrowed from its key; `out` has `N` writable bytes.
    if unsafe { sys::BN_bn2bin_padded(out.as_mut_ptr(), N, bn) } == 1 {
        Ok(out)
    } else {
        Err(BlindError::Key)
    }
}

struct Bn(NonNull<sys::BIGNUM>);

impl Bn {
    fn new() -> Result<Self, BlindError> {
        // SAFETY: returns a new big number or null.
        NonNull::new(unsafe { sys::BN_new() })
            .map(Self)
            .ok_or(BlindError::Operation)
    }

    fn of(bytes: &[u8]) -> Result<Self, BlindError> {
        // SAFETY: `bytes` is readable for its length; a null `ret` asks for a new big number.
        NonNull::new(unsafe { sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut()) })
            .map(Self)
            .ok_or(BlindError::Operation)
    }

    const fn ptr(&self) -> *mut sys::BIGNUM {
        self.0.as_ptr()
    }

    fn bytes(&self) -> Result<[u8; MODULUS_LEN], BlindError> {
        padded(self.0.as_ptr()).map_err(|_| BlindError::Operation)
    }
}

impl Drop for Bn {
    fn drop(&mut self) {
        // SAFETY: the big number is owned here and freed once.
        unsafe { sys::BN_clear_free(self.0.as_ptr()) }
    }
}

struct Ctx(NonNull<sys::BN_CTX>);

impl Ctx {
    fn new() -> Result<Self, BlindError> {
        // SAFETY: returns a new context or null.
        NonNull::new(unsafe { sys::BN_CTX_new() })
            .map(Self)
            .ok_or(BlindError::Operation)
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: the context is owned here and freed once.
        unsafe { sys::BN_CTX_free(self.0.as_ptr()) }
    }
}

#[cfg(test)]
mod tests;
