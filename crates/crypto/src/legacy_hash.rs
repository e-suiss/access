//! Password hashes imported from another identity provider (§12.3.7, §10.2.1, TN-85, CR-37): parsed from
//! their stored strings (the Kratos import list) and verified once at login, after which the
//! account plane stores Argon2id. bcrypt, scrypt and MD5 are pure Rust here; PBKDF2, SHA and
//! AES come from aws-lc-rs (OP-153 m.11 (h)). Argon2 strings belong to the account plane.

mod b64;
mod blowfish;
mod blowfish_tables;
mod crypt;
mod md5;
mod scrypt;
mod transform;

use core::fmt;
use core::num::NonZeroU32;

use aws_lc_rs::cipher::{AES_256, EncryptingKey, UnboundCipherKey};
use aws_lc_rs::pbkdf2;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use crypt::Digest;
pub use transform::{Pepper, Prehash, Transform};

use crate::dit::DitGuard;

/// Highest bcrypt cost verified.
pub const MAX_BCRYPT_COST: u32 = 20;
/// Most memory one scrypt verification may take (`128 · r · N` bytes).
pub const MAX_SCRYPT_BYTES: u64 = 256 * 1024 * 1024;
/// Highest scrypt parallelism verified.
pub const MAX_SCRYPT_P: u32 = 16;
/// Most PBKDF2 iterations verified.
pub const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
/// Most sha-crypt rounds verified.
pub const MAX_CRYPT_ROUNDS: u32 = 10_000_000;

const MAX_FIELD: usize = 1024;

/// Why a stored legacy hash could not be read or checked. Never names the password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LegacyHashError {
    /// An Argon2 PHC string: the account plane verifies it.
    #[error("argon2 hashes are verified by the account plane")]
    Argon2,
    /// No known scheme prefix.
    #[error("unknown legacy hash scheme")]
    Unknown,
    /// A known scheme with a broken body.
    #[error("malformed legacy hash")]
    Malformed,
    /// Parameters beyond the verifier's bounds.
    #[error("legacy hash parameters exceed the verifier's bounds")]
    Bound,
    /// A malformed pre-hash or pepper spec.
    #[error("malformed hash transform")]
    Transform,
    /// The primitive failed.
    #[error("legacy hash computation failed")]
    Compute,
}

/// The PBKDF2 PRF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pbkdf2Prf {
    /// HMAC-SHA-1.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// A parsed legacy hash. Its material never prints.
pub enum LegacyHash {
    /// bcrypt `$2a$`, `$2b$`, `$2y$`.
    Bcrypt {
        /// log2 rounds.
        cost: u32,
        /// The salt.
        salt: [u8; 16],
        /// The 31-character hash part.
        hash: String,
    },
    /// scrypt in PHC form.
    Scrypt {
        /// `N`.
        n: u64,
        /// Block size.
        r: u32,
        /// Parallelism.
        p: u32,
        /// The salt.
        salt: Vec<u8>,
        /// The derived key.
        hash: Vec<u8>,
    },
    /// Firebase's modified scrypt.
    FirebaseScrypt {
        /// `N`.
        n: u64,
        /// Block size (Firebase "rounds").
        r: u32,
        /// Parallelism.
        p: u32,
        /// The salt.
        salt: Vec<u8>,
        /// The stored hash.
        hash: Vec<u8>,
        /// The project's salt separator.
        separator: Vec<u8>,
        /// The project's signer key.
        signer_key: Vec<u8>,
    },
    /// PBKDF2 in PHC or passlib form.
    Pbkdf2 {
        /// The PRF.
        prf: Pbkdf2Prf,
        /// Iterations.
        iterations: u32,
        /// The salt.
        salt: Vec<u8>,
        /// The derived key.
        hash: Vec<u8>,
    },
    /// md5-crypt `$1$`.
    Md5Crypt {
        /// The salt text.
        salt: String,
        /// The 22-character hash part.
        hash: String,
    },
    /// sha-crypt `$5$` or `$6$`.
    ShaCrypt {
        /// SHA-512 (`$6$`), else SHA-256.
        sha512: bool,
        /// Rounds.
        rounds: u32,
        /// The salt text.
        salt: String,
        /// The hash part.
        hash: String,
    },
    /// LDAP `{SHA}`, `{SSHA}`, `{SSHA256}`, `{SSHA512}`, `{MD5}`, `{SMD5}`: digest of
    /// password ‖ salt.
    Ldap {
        /// The digest.
        digest: Digest,
        /// The salt; empty when unsalted.
        salt: Vec<u8>,
        /// The digest value.
        hash: Vec<u8>,
        /// A salted variant.
        salted: bool,
    },
    /// Kratos `$md5$`, `$sha1$`, `$sha256$`, `$sha512$` with an optional `pf` pattern.
    Pattern {
        /// The digest.
        digest: Digest,
        /// `{SALT}` and `{PASSWORD}` placeholders; `None` hashes the password alone.
        pattern: Option<Vec<u8>>,
        /// The salt.
        salt: Vec<u8>,
        /// The digest value.
        hash: Vec<u8>,
    },
}

impl fmt::Debug for LegacyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LegacyHash({})", self.scheme())
    }
}

/// Whether `stored` is an Argon2 PHC string, which the account plane verifies itself.
#[must_use]
pub fn is_argon2(stored: &str) -> bool {
    ["$argon2id$", "$argon2i$", "$argon2d$"]
        .iter()
        .any(|p| stored.starts_with(p))
}

fn dec(s: &str) -> Result<Vec<u8>, LegacyHashError> {
    if s.len() > MAX_FIELD {
        return Err(LegacyHashError::Malformed);
    }
    b64::decode(s).ok_or(LegacyHashError::Malformed)
}

fn dec_nonempty(s: &str) -> Result<Vec<u8>, LegacyHashError> {
    let v = dec(s)?;
    if v.is_empty() {
        return Err(LegacyHashError::Malformed);
    }
    Ok(v)
}

fn num<T: core::str::FromStr>(s: &str) -> Result<T, LegacyHashError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LegacyHashError::Malformed);
    }
    s.parse().map_err(|_| LegacyHashError::Malformed)
}

fn params<'a>(s: &'a str, keys: &[&str]) -> Result<Vec<(&'a str, &'a str)>, LegacyHashError> {
    let mut out = Vec::new();
    for kv in s.split(',') {
        let (k, v) = kv.split_once('=').ok_or(LegacyHashError::Malformed)?;
        if !keys.contains(&k) || out.iter().any(|(seen, _)| *seen == k) {
            return Err(LegacyHashError::Malformed);
        }
        out.push((k, v));
    }
    Ok(out)
}

fn param<'a>(p: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
    p.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// `N`, `r`, `p` of an scrypt hash; Kratos writes `N` itself under `ln`, PHC writes log2 `N`.
fn scrypt_params(s: &str) -> Result<(u64, u32, u32), LegacyHashError> {
    let p = params(s, &["ln", "r", "p"])?;
    let ln: u64 = num(param(&p, "ln").ok_or(LegacyHashError::Malformed)?)?;
    let r: u32 = num(param(&p, "r").ok_or(LegacyHashError::Malformed)?)?;
    let par: u32 = num(param(&p, "p").unwrap_or("1"))?;
    // TN-85
    let n = if ln < 64 {
        1u64.checked_shl(u32::try_from(ln).map_err(|_| LegacyHashError::Malformed)?)
            .ok_or(LegacyHashError::Malformed)?
    } else if ln.is_power_of_two() {
        ln
    } else {
        return Err(LegacyHashError::Malformed);
    };
    if n < 2 || r == 0 || par == 0 {
        return Err(LegacyHashError::Malformed);
    }
    let bytes = n
        .checked_mul(u64::from(r))
        .and_then(|v| v.checked_mul(128))
        .ok_or(LegacyHashError::Bound)?;
    if bytes > MAX_SCRYPT_BYTES || par > MAX_SCRYPT_P {
        return Err(LegacyHashError::Bound);
    }
    Ok((n, r, par))
}

fn parse_bcrypt(rest: &str) -> Result<LegacyHash, LegacyHashError> {
    let (cost, body) = rest.split_once('$').ok_or(LegacyHashError::Malformed)?;
    if cost.len() != 2 || body.len() != 53 || !body.is_ascii() {
        return Err(LegacyHashError::Malformed);
    }
    let cost: u32 = num(cost)?;
    if cost < 4 {
        return Err(LegacyHashError::Malformed);
    }
    if cost > MAX_BCRYPT_COST {
        return Err(LegacyHashError::Bound);
    }
    let (salt_text, hash) = body
        .split_at_checked(22)
        .ok_or(LegacyHashError::Malformed)?;
    let decoded = b64::decode_bcrypt(salt_text).ok_or(LegacyHashError::Malformed)?;
    let salt: [u8; 16] = decoded
        .get(..16)
        .and_then(|s| s.try_into().ok())
        .ok_or(LegacyHashError::Malformed)?;
    if b64::decode_bcrypt(hash).is_none() {
        return Err(LegacyHashError::Malformed);
    }
    Ok(LegacyHash::Bcrypt {
        cost,
        salt,
        hash: hash.to_owned(),
    })
}

fn crypt_salt_ok(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_graphic() && b != b'$' && b != b':')
}

fn crypt_hash_ok(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
}

fn parse_sha_crypt(sha512: bool, rest: &str) -> Result<LegacyHash, LegacyHashError> {
    let parts: Vec<&str> = rest.split('$').collect();
    let (rounds, salt, hash) = match parts.as_slice() {
        [r, s, h] => {
            let n = r
                .strip_prefix("rounds=")
                .ok_or(LegacyHashError::Malformed)?;
            (num::<u32>(n)?, *s, *h)
        }
        [s, h] => (crypt::SHA_CRYPT_DEFAULT_ROUNDS, *s, *h),
        _ => return Err(LegacyHashError::Malformed),
    };
    if rounds > MAX_CRYPT_ROUNDS {
        return Err(LegacyHashError::Bound);
    }
    let len = if sha512 { 86 } else { 43 };
    if salt.len() > MAX_FIELD || !crypt_salt_ok(salt) || !crypt_hash_ok(hash, len) {
        return Err(LegacyHashError::Malformed);
    }
    Ok(LegacyHash::ShaCrypt {
        sha512,
        rounds,
        salt: salt.to_owned(),
        hash: hash.to_owned(),
    })
}

fn parse_pbkdf2(prf: Pbkdf2Prf, rest: &str) -> Result<LegacyHash, LegacyHashError> {
    let parts: Vec<&str> = rest.split('$').collect();
    let [p, salt, hash] = parts.as_slice() else {
        return Err(LegacyHashError::Malformed);
    };
    let iterations: u32 = if p.bytes().all(|b| b.is_ascii_digit()) {
        num(p)?
    } else {
        let kv = params(p, &["i", "l"])?;
        num(param(&kv, "i").ok_or(LegacyHashError::Malformed)?)?
    };
    if iterations == 0 {
        return Err(LegacyHashError::Malformed);
    }
    if iterations > MAX_PBKDF2_ITERATIONS {
        return Err(LegacyHashError::Bound);
    }
    Ok(LegacyHash::Pbkdf2 {
        prf,
        iterations,
        salt: dec(salt)?,
        hash: dec_nonempty(hash)?,
    })
}

fn parse_ldap(rest: &str) -> Result<LegacyHash, LegacyHashError> {
    let (label, body) = rest.split_once('}').ok_or(LegacyHashError::Malformed)?;
    let (digest, salted) = match label {
        "SHA" => (Digest::Sha1, false),
        "SSHA" => (Digest::Sha1, true),
        "SHA256" => (Digest::Sha256, false),
        "SSHA256" => (Digest::Sha256, true),
        "SHA512" => (Digest::Sha512, false),
        "SSHA512" => (Digest::Sha512, true),
        "MD5" => (Digest::Md5, false),
        "SMD5" => (Digest::Md5, true),
        _ => return Err(LegacyHashError::Unknown),
    };
    let raw = dec(body)?;
    let len = match digest {
        Digest::Md5 => 16,
        Digest::Sha1 => 20,
        Digest::Sha256 => 32,
        Digest::Sha512 => 64,
    };
    let (hash, salt) = raw
        .split_at_checked(len)
        .ok_or(LegacyHashError::Malformed)?;
    if salted == salt.is_empty() {
        return Err(LegacyHashError::Malformed);
    }
    Ok(LegacyHash::Ldap {
        digest,
        salt: salt.to_vec(),
        hash: hash.to_vec(),
        salted,
    })
}

fn parse_pattern(digest: Digest, rest: &str) -> Result<LegacyHash, LegacyHashError> {
    let parts: Vec<&str> = rest.split('$').collect();
    match parts.as_slice() {
        [hash] => Ok(LegacyHash::Pattern {
            digest,
            pattern: None,
            salt: Vec::new(),
            hash: dec_nonempty(hash)?,
        }),
        [pf, salt, hash] => {
            let pf = pf.strip_prefix("pf=").ok_or(LegacyHashError::Malformed)?;
            Ok(LegacyHash::Pattern {
                digest,
                pattern: Some(dec_nonempty(pf)?),
                salt: dec(salt)?,
                hash: dec_nonempty(hash)?,
            })
        }
        _ => Err(LegacyHashError::Malformed),
    }
}

fn parse_firebase(rest: &str) -> Result<LegacyHash, LegacyHashError> {
    let parts: Vec<&str> = rest.split('$').collect();
    let [p, salt, hash, sep, key] = parts.as_slice() else {
        return Err(LegacyHashError::Malformed);
    };
    let (n, r, p) = scrypt_params(p)?;
    let hash = dec_nonempty(hash)?;
    let signer_key = dec_nonempty(key)?;
    if hash.len() != signer_key.len() {
        return Err(LegacyHashError::Malformed);
    }
    Ok(LegacyHash::FirebaseScrypt {
        n,
        r,
        p,
        salt: dec(salt)?,
        hash,
        separator: dec(sep)?,
        signer_key,
    })
}

fn substitute(pattern: &[u8], salt: &[u8], password: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        pattern
            .len()
            .saturating_add(salt.len())
            .saturating_add(password.len()),
    ));
    let mut rest = pattern;
    while let Some((first, tail)) = rest.split_first() {
        if let Some(t) = rest.strip_prefix(b"{SALT}".as_slice()) {
            out.extend_from_slice(salt);
            rest = t;
        } else if let Some(t) = rest.strip_prefix(b"{PASSWORD}".as_slice()) {
            out.extend_from_slice(password);
            rest = t;
        } else {
            out.push(*first);
            rest = tail;
        }
    }
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // CR-39 m.3
    let _dit = DitGuard::new();
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn firebase(
    password: &[u8],
    n: u64,
    r: u32,
    p: u32,
    salt_sep: (&[u8], &[u8]),
    signer_key: &[u8],
) -> Result<Vec<u8>, LegacyHashError> {
    let salt = [salt_sep.0, salt_sep.1].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, &salt, n, r, p, key.as_mut_slice()).ok_or(LegacyHashError::Compute)?;
    let unbound = || UnboundCipherKey::new(&AES_256, key.as_slice());
    let ecb = EncryptingKey::ecb(unbound().map_err(|_| LegacyHashError::Compute)?)
        .map_err(|_| LegacyHashError::Compute)?;
    let mut out = Vec::with_capacity(signer_key.len());
    let mut counter: u128 = 0;
    for chunk in signer_key.chunks(16) {
        let mut block = counter.to_be_bytes();
        ecb.encrypt(&mut block)
            .map_err(|_| LegacyHashError::Compute)?;
        out.extend(chunk.iter().zip(block.iter()).map(|(a, b)| a ^ b));
        counter = counter.wrapping_add(1);
    }
    Ok(out)
}

impl LegacyHash {
    /// Parses a stored legacy hash string.
    ///
    /// # Errors
    /// [`LegacyHashError::Argon2`] for Argon2 PHC strings; [`LegacyHashError::Unknown`] for an
    /// unknown or prefix-less scheme (bare hex is ambiguous); [`LegacyHashError::Malformed`];
    /// [`LegacyHashError::Bound`] for parameters beyond the bounds.
    pub fn parse(stored: &str) -> Result<Self, LegacyHashError> {
        // TN-85, OP-153 m.11 (h)
        if is_argon2(stored) {
            return Err(LegacyHashError::Argon2);
        }
        if stored.len() > MAX_FIELD.saturating_mul(4) || !stored.is_ascii() {
            return Err(LegacyHashError::Malformed);
        }
        if let Some(rest) = stored.strip_prefix('{') {
            return parse_ldap(rest);
        }
        let rest = stored.strip_prefix('$').ok_or(LegacyHashError::Unknown)?;
        let (id, body) = rest.split_once('$').ok_or(LegacyHashError::Unknown)?;
        match id {
            "2a" | "2b" | "2y" => parse_bcrypt(body),
            "scrypt" => {
                let parts: Vec<&str> = body.split('$').collect();
                let [p, salt, hash] = parts.as_slice() else {
                    return Err(LegacyHashError::Malformed);
                };
                let (n, r, p) = scrypt_params(p)?;
                Ok(Self::Scrypt {
                    n,
                    r,
                    p,
                    salt: dec(salt)?,
                    hash: dec_nonempty(hash)?,
                })
            }
            "firescrypt" => parse_firebase(body),
            "pbkdf2-sha1" | "pbkdf2" => parse_pbkdf2(Pbkdf2Prf::Sha1, body),
            "pbkdf2-sha256" => parse_pbkdf2(Pbkdf2Prf::Sha256, body),
            "pbkdf2-sha512" => parse_pbkdf2(Pbkdf2Prf::Sha512, body),
            "1" => {
                let (salt, hash) = body.split_once('$').ok_or(LegacyHashError::Malformed)?;
                if salt.len() > 8 || !crypt_salt_ok(salt) || !crypt_hash_ok(hash, 22) {
                    return Err(LegacyHashError::Malformed);
                }
                Ok(Self::Md5Crypt {
                    salt: salt.to_owned(),
                    hash: hash.to_owned(),
                })
            }
            "5" => parse_sha_crypt(false, body),
            "6" => parse_sha_crypt(true, body),
            "md5" => parse_pattern(Digest::Md5, body),
            "sha1" => parse_pattern(Digest::Sha1, body),
            "sha256" => parse_pattern(Digest::Sha256, body),
            "sha512" => parse_pattern(Digest::Sha512, body),
            _ => Err(LegacyHashError::Unknown),
        }
    }

    /// The stable scheme label (`^[a-z0-9][a-z0-9_.-]{0,31}$`); the credential's algorithm
    /// column holds `legacy-<scheme>`.
    #[must_use]
    pub const fn scheme(&self) -> &'static str {
        match self {
            Self::Bcrypt { .. } => "bcrypt",
            Self::Scrypt { .. } => "scrypt",
            Self::FirebaseScrypt { .. } => "firebase-scrypt",
            Self::Pbkdf2 { prf, .. } => match prf {
                Pbkdf2Prf::Sha1 => "pbkdf2-sha1",
                Pbkdf2Prf::Sha256 => "pbkdf2-sha256",
                Pbkdf2Prf::Sha512 => "pbkdf2-sha512",
            },
            Self::Md5Crypt { .. } => "md5-crypt",
            Self::ShaCrypt { sha512: false, .. } => "sha256-crypt",
            Self::ShaCrypt { sha512: true, .. } => "sha512-crypt",
            Self::Ldap { digest, salted, .. } => match (digest, salted) {
                (Digest::Md5, false) => "ldap-md5",
                (Digest::Md5, true) => "ldap-smd5",
                (Digest::Sha1, false) => "ldap-sha",
                (Digest::Sha1, true) => "ldap-ssha",
                (Digest::Sha256, false) => "ldap-sha256",
                (Digest::Sha256, true) => "ldap-ssha256",
                (Digest::Sha512, false) => "ldap-sha512",
                (Digest::Sha512, true) => "ldap-ssha512",
            },
            Self::Pattern { digest, .. } => match digest {
                Digest::Md5 => "md5",
                Digest::Sha1 => "sha1",
                Digest::Sha256 => "sha256",
                Digest::Sha512 => "sha512",
            },
        }
    }

    /// Checks `password` (after `transform`) against the hash.
    ///
    /// # Errors
    /// [`LegacyHashError::Compute`] when the primitive fails; never accepts on error.
    pub fn verify(&self, transform: &Transform, password: &[u8]) -> Result<bool, LegacyHashError> {
        verify(self, transform, password)
    }
}

/// Iterations of the FIPS profile's password hash (CR-15, CR-36 m.1).
pub const FIPS_PBKDF2_ITERATIONS: u32 = 600_000;

/// The PHC string `$pbkdf2-sha256$i=<iterations>$<salt>$<hash>` of `password` with a 32-byte
/// PBKDF2-HMAC-SHA-256 output: the FIPS profile's password hash (CR-15, CR-36, OP-158 m.3 (y)).
/// [`LegacyHash::parse`] reads it back.
#[must_use]
pub fn pbkdf2_sha256(iterations: NonZeroU32, salt: &[u8; 16], password: &[u8]) -> String {
    let mut out = Zeroizing::new([0_u8; 32]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        out.as_mut_slice(),
    );
    format!(
        "$pbkdf2-sha256$i={iterations}${}${}",
        b64::encode_standard(salt),
        b64::encode_standard(out.as_slice())
    )
}

/// Checks `password` (after `transform`) against `hash`; the final comparison is constant
/// time.
///
/// # Errors
/// [`LegacyHashError::Compute`] when the primitive fails; never accepts on error.
pub fn verify(
    hash: &LegacyHash,
    transform: &Transform,
    password: &[u8],
) -> Result<bool, LegacyHashError> {
    // TN-85, CR-37
    let pw = transform.apply(password);
    let pw: &[u8] = &pw;
    Ok(match hash {
        LegacyHash::Bcrypt { cost, salt, hash } => {
            let out = blowfish::bcrypt(*cost, salt, pw).ok_or(LegacyHashError::Compute)?;
            let mine = b64::encode_bcrypt(out.get(..23).ok_or(LegacyHashError::Compute)?);
            ct_eq(mine.as_bytes(), hash.as_bytes())
        }
        LegacyHash::Scrypt {
            n,
            r,
            p,
            salt,
            hash,
        } => {
            let mut out = Zeroizing::new(vec![0u8; hash.len()]);
            scrypt::scrypt(pw, salt, *n, *r, *p, &mut out).ok_or(LegacyHashError::Compute)?;
            ct_eq(&out, hash)
        }
        LegacyHash::FirebaseScrypt {
            n,
            r,
            p,
            salt,
            hash,
            separator,
            signer_key,
        } => {
            let out = firebase(pw, *n, *r, *p, (salt, separator), signer_key)?;
            ct_eq(&out, hash)
        }
        LegacyHash::Pbkdf2 {
            prf,
            iterations,
            salt,
            hash,
        } => {
            let alg = match prf {
                Pbkdf2Prf::Sha1 => pbkdf2::PBKDF2_HMAC_SHA1,
                Pbkdf2Prf::Sha256 => pbkdf2::PBKDF2_HMAC_SHA256,
                Pbkdf2Prf::Sha512 => pbkdf2::PBKDF2_HMAC_SHA512,
            };
            let iterations = NonZeroU32::new(*iterations).ok_or(LegacyHashError::Compute)?;
            let mut out = Zeroizing::new(vec![0u8; hash.len()]);
            pbkdf2::derive(alg, iterations, salt, pw, &mut out);
            ct_eq(&out, hash)
        }
        LegacyHash::Md5Crypt { salt, hash } => {
            let mine = crypt::md5_crypt(pw, salt.as_bytes());
            ct_eq(mine.as_bytes(), hash.as_bytes())
        }
        LegacyHash::ShaCrypt {
            sha512,
            rounds,
            salt,
            hash,
        } => {
            let mine = crypt::sha_crypt(*sha512, pw, salt.as_bytes(), *rounds);
            ct_eq(mine.as_bytes(), hash.as_bytes())
        }
        LegacyHash::Ldap {
            digest, salt, hash, ..
        } => ct_eq(&digest.of(&[pw, salt]), hash),
        LegacyHash::Pattern {
            digest,
            pattern,
            salt,
            hash,
        } => {
            let input = match pattern {
                Some(p) => substitute(p, salt, pw),
                None => Zeroizing::new(pw.to_vec()),
            };
            ct_eq(&digest.of(&[&input]), hash)
        }
    })
}

#[cfg(test)]
mod tests;
