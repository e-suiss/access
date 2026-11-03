//! Passwords (§10.2.1, IDP-3, CR-36, CR-37): NIST 800-63B-4 policy after NFKC, Argon2id in
//! PHC string form, rehash when the stored parameters are weaker than the policy's, and the
//! hash semaphore's size. Pure computation; the app layer runs it off the reactor.

use access_crypto::Secret;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use unicode_normalization::UnicodeNormalization;

/// Shortest password, in characters after NFKC (NIST 800-63B-4).
pub const MIN_CHARS: usize = 8;

/// Longest password, in characters after NFKC; NIST asks for at least 64 (PD).
pub const MAX_CHARS: usize = 128;

/// Longest input a login hashes, in bytes; anything longer cannot match a stored password.
pub const MAX_LOGIN_BYTES: usize = 4 * MAX_CHARS;

/// The PHC algorithm identifier.
pub const ALGORITHM: &str = "argon2id";

/// Why a new password was refused (no composition rules, no rotation: NIST 800-63B-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasswordRejected {
    /// Shorter than [`MIN_CHARS`].
    #[error("password shorter than {min} characters")]
    TooShort {
        /// The minimum.
        min: usize,
    },
    /// Longer than [`MAX_CHARS`].
    #[error("password longer than {max} characters")]
    TooLong {
        /// The maximum.
        max: usize,
    },
    /// Listed in the breached-password corpus (IDP-3).
    #[error("password appears in a breach corpus")]
    Breached,
}

impl PasswordRejected {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooShort { .. } => "password-too-short",
            Self::TooLong { .. } => "password-too-long",
            Self::Breached => "password-breached",
        }
    }
}

/// A password after NFKC. Never printed or compared directly.
#[derive(Clone)]
pub struct Password(Secret<String>);

fn nfkc(raw: &str) -> Secret<String> {
    Secret::new(raw.nfkc().collect())
}

impl Password {
    /// A new password, checked against the policy (§10.2.1).
    ///
    /// # Errors
    /// [`PasswordRejected`].
    pub fn new(raw: &str) -> Result<Self, PasswordRejected> {
        let p = nfkc(raw);
        let n = p.expose().chars().count();
        if n < MIN_CHARS {
            return Err(PasswordRejected::TooShort { min: MIN_CHARS });
        }
        if n > MAX_CHARS {
            return Err(PasswordRejected::TooLong { max: MAX_CHARS });
        }
        Ok(Self(p))
    }

    /// A presented password at login, without the policy: a stored password may predate it.
    /// `None` when the input is too long to be any stored password.
    #[must_use]
    pub fn presented(raw: &str) -> Option<Self> {
        if raw.len() > MAX_LOGIN_BYTES {
            return None;
        }
        let p = nfkc(raw);
        (p.expose().chars().count() <= MAX_CHARS).then_some(Self(p))
    }

    /// The UTF-8 bytes, for hashing.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.expose().as_bytes()
    }
}

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// A realm asked for parameters below the canonical ones (OP-33: raise only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Argon2 parameters may only be raised")]
pub struct WeakerParams;

/// Hashing failed: bad parameters or a malformed stored hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HashFailure {
    /// The parameters are outside Argon2's limits.
    #[error("argon2 parameters")]
    Params,
    /// The stored string is not an Argon2 PHC string.
    #[error("malformed password hash")]
    Malformed,
    /// Argon2 refused the input.
    #[error("argon2")]
    Compute,
}

impl Argon2Params {
    /// CR-36: m = 7 MiB, t = 5, p = 1.
    pub const CANONICAL: Self = Self {
        m_kib: 7 * 1024,
        t: 5,
        p: 1,
    };

    /// A realm's parameters: each at least the canonical value (OP-33, §17.5.2).
    ///
    /// # Errors
    /// [`WeakerParams`].
    pub const fn for_realm(m_kib: u32, t: u32, p: u32) -> Result<Self, WeakerParams> {
        let c = Self::CANONICAL;
        if m_kib < c.m_kib || t < c.t || p < c.p {
            return Err(WeakerParams);
        }
        Ok(Self { m_kib, t, p })
    }

    /// Whether a hash made with `self` is weaker than `policy` asks.
    #[must_use]
    pub const fn weaker_than(&self, policy: &Self) -> bool {
        self.m_kib < policy.m_kib || self.t < policy.t || self.p < policy.p
    }

    fn argon2(&self) -> Result<Argon2<'static>, HashFailure> {
        let params =
            Params::new(self.m_kib, self.t, self.p, None).map_err(|_| HashFailure::Params)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// The PHC string of `password` under `params` with `salt`.
///
/// # Errors
/// [`HashFailure`].
pub fn hash(
    params: &Argon2Params,
    password: &Password,
    salt: &[u8; 16],
) -> Result<Secret<String>, HashFailure> {
    let h = params
        .argon2()?
        .hash_password_with_salt(password.bytes(), salt)
        .map_err(|_| HashFailure::Compute)?;
    Ok(Secret::new(h.to_string()))
}

/// The result of checking a password against its stored hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verification {
    /// The password matches.
    pub matched: bool,
    /// The stored hash is weaker than the policy: rehash on success (CR-37).
    pub rehash: bool,
}

/// The parameters of a stored PHC string; `None` when it is not Argon2id v19.
///
/// # Errors
/// [`HashFailure::Malformed`].
pub fn stored_params(phc: &str) -> Result<Option<Argon2Params>, HashFailure> {
    let h = PasswordHash::new(phc).map_err(|_| HashFailure::Malformed)?;
    if h.algorithm.as_str() != ALGORITHM || h.version != Some(0x13) {
        return Ok(None);
    }
    let p = Params::try_from(&h).map_err(|_| HashFailure::Malformed)?;
    Ok(Some(Argon2Params {
        m_kib: p.m_cost(),
        t: p.t_cost(),
        p: p.p_cost(),
    }))
}

/// Checks `password` against the stored PHC string with its own parameters, and whether it
/// needs a rehash under `policy`.
///
/// # Errors
/// [`HashFailure`] for a malformed or foreign hash.
pub fn verify(
    password: &Password,
    phc: &Secret<String>,
    policy: &Argon2Params,
) -> Result<Verification, HashFailure> {
    let stored = stored_params(phc.expose())?.ok_or(HashFailure::Malformed)?;
    let matched = match stored
        .argon2()?
        .verify_password(password.bytes(), phc.expose().as_str())
    {
        Ok(()) => true,
        Err(argon2::password_hash::Error::PasswordInvalid) => false,
        Err(_) => return Err(HashFailure::Malformed),
    };
    Ok(Verification {
        matched,
        rehash: stored.weaker_than(policy),
    })
}

/// The hash semaphore's size (CR-36 m.3, OP-146 m.4 (f)):
/// `min(cores, ⌊budget × 0.5 / m⌋)`, at least one. Without a budget the cores decide.
#[must_use]
pub fn permits(cores: usize, budget_bytes: Option<u64>, params: &Argon2Params) -> usize {
    let per_hash = u64::from(params.m_kib)
        .saturating_mul(1024)
        .saturating_mul(u64::from(params.p));
    let by_memory = budget_bytes.map_or(usize::MAX, |b| {
        let n = (b / 2).checked_div(per_hash).unwrap_or(0);
        usize::try_from(n).unwrap_or(usize::MAX)
    });
    cores.min(by_memory).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIGHT: Argon2Params = Argon2Params {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    // IDP-3, OP-146
    #[test]
    fn policy_counts_characters_after_nfkc() {
        assert_eq!(
            Password::new("short").err(),
            Some(PasswordRejected::TooShort { min: 8 })
        );
        assert!(Password::new("ﬁﬁﬁ").is_err());
        assert!(Password::new("ﬁﬁﬁﬁ").is_ok());
        assert!(Password::new(&"é".repeat(MAX_CHARS)).is_ok());
        assert_eq!(
            Password::new(&"a".repeat(MAX_CHARS + 1)).err(),
            Some(PasswordRejected::TooLong { max: MAX_CHARS })
        );
        assert!(Password::new("password").is_ok());
        assert!(Password::presented(&"a".repeat(MAX_LOGIN_BYTES + 1)).is_none());
        assert!(Password::presented("x").is_some());
    }

    // OP-146 m.5 (j)
    #[test]
    fn compatibility_forms_hash_alike() {
        let a = Password::new("Ｐａｓｓｗｏｒｄ１").unwrap();
        let b = Password::new("Password1").unwrap();
        let salt = [7; 16];
        let ha = hash(&LIGHT, &a, &salt).unwrap();
        assert!(verify(&b, &ha, &LIGHT).unwrap().matched);
    }

    // CR-36, CR-37
    #[test]
    fn phc_round_trip_and_rehash() {
        let pw = Password::new("correct horse").unwrap();
        let h = hash(&LIGHT, &pw, &[1; 16]).unwrap();
        assert!(h.expose().starts_with("$argon2id$v=19$m=64,t=1,p=1$"));
        assert_eq!(stored_params(h.expose()).unwrap(), Some(LIGHT));
        let v = verify(&pw, &h, &Argon2Params::CANONICAL).unwrap();
        assert_eq!(
            v,
            Verification {
                matched: true,
                rehash: true
            }
        );
        let v = verify(&Password::new("wrong horse").unwrap(), &h, &LIGHT).unwrap();
        assert_eq!(
            v,
            Verification {
                matched: false,
                rehash: false
            }
        );
        assert_eq!(
            verify(&pw, &Secret::new("$2b$10$abc".to_owned()), &LIGHT),
            Err(HashFailure::Malformed)
        );
    }

    // CR-36, OP-33
    #[test]
    fn realms_only_raise() {
        assert_eq!(
            Argon2Params::CANONICAL,
            Argon2Params {
                m_kib: 7168,
                t: 5,
                p: 1
            }
        );
        assert!(Argon2Params::for_realm(7168, 4, 1).is_err());
        assert!(Argon2Params::for_realm(4096, 5, 1).is_err());
        assert!(Argon2Params::for_realm(19 * 1024, 5, 1).is_ok());
    }

    // CR-36, OP-146
    #[test]
    fn semaphore_size() {
        let c = Argon2Params::CANONICAL;
        assert_eq!(permits(8, None, &c), 8);
        assert_eq!(permits(8, Some(70 * 1024 * 1024), &c), 5);
        assert_eq!(permits(2, Some(1 << 40), &c), 2);
        assert_eq!(permits(8, Some(1024), &c), 1);
        assert_eq!(permits(0, None, &c), 1);
    }
}
