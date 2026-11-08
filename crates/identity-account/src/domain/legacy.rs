//! Imported passwords (§12.3.7, §10.2.1, TN-85, CR-37): what an import line's hash becomes in
//! the credential table, and its check at sign-in. An Argon2id v19 hash is stored as it is and
//! rehashed by the usual rule; every other scheme is kept sealed as `legacy-<scheme>` with its
//! pre-hash and pepper as data, checked once, and replaced by Argon2id at the first successful
//! sign-in. An account that brings no hash at all is `legacy-idp`: its first sign-in asks the
//! previous identity provider, and an unanswered question fails the sign-in.

use access_crypto::legacy_hash::{self, LegacyHash, LegacyHashError, Transform};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

use crate::domain::password::{ALGORITHM, Password};

/// The prefix of every imported scheme's `algorithm`.
pub const PREFIX: &str = "legacy-";

/// An account whose password the previous identity provider still checks.
pub const IDP: &str = "legacy-idp";

/// Argon2 strings other than Argon2id v19 (Argon2i, Argon2d, version 16).
pub const ARGON2: &str = "legacy-argon2";

/// The highest Argon2 memory, KiB, an imported string may ask for.
pub const MAX_ARGON2_KIB: u32 = 256 * 1024;

/// The most Argon2 passes and lanes an imported string may ask for.
pub const MAX_ARGON2_T: u32 = 64;

/// The most Argon2 lanes.
pub const MAX_ARGON2_P: u32 = 16;

/// Why an import line's hash was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImportRejected {
    /// Not a known scheme, malformed, or past the verifier's bounds.
    #[error("unsupported or malformed password hash ({0})")]
    Hash(LegacyHashError),
    /// A pre-hash or pepper given for an Argon2 string.
    #[error("an Argon2 hash takes no pre-hash or pepper")]
    Argon2Transform,
}

/// What an imported hash is stored as.
#[derive(Clone, PartialEq, Eq)]
pub struct Stored {
    /// The credential's `algorithm`.
    pub algorithm: String,
    /// The text sealed as the credential's secret.
    pub text: String,
}

impl core::fmt::Debug for Stored {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stored")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

fn argon2_bounded(h: &PasswordHash) -> bool {
    let p = |name: &str| h.params.get_decimal(name).unwrap_or(0);
    (1..=MAX_ARGON2_KIB).contains(&p("m"))
        && (1..=MAX_ARGON2_T).contains(&p("t"))
        && (1..=MAX_ARGON2_P).contains(&p("p"))
}

/// What `hash`, with the optional pre-hash/pepper `transform`, is stored as.
///
/// # Errors
/// [`ImportRejected`].
pub fn classify(hash: &str, transform: Option<&str>) -> Result<Stored, ImportRejected> {
    let transform = transform.map(str::trim).filter(|t| !t.is_empty());
    if legacy_hash::is_argon2(hash) {
        if transform.is_some() {
            return Err(ImportRejected::Argon2Transform);
        }
        let h = PasswordHash::new(hash)
            .map_err(|_| ImportRejected::Hash(LegacyHashError::Malformed))?;
        if !argon2_bounded(&h) {
            return Err(ImportRejected::Hash(LegacyHashError::Bound));
        }
        let algorithm = if h.algorithm.as_str() == ALGORITHM && h.version == Some(0x13) {
            ALGORITHM.to_owned()
        } else {
            ARGON2.to_owned()
        };
        return Ok(Stored {
            algorithm,
            text: hash.to_owned(),
        });
    }
    let parsed = LegacyHash::parse(hash).map_err(ImportRejected::Hash)?;
    let spec = transform.unwrap_or_default();
    Transform::parse(spec).map_err(ImportRejected::Hash)?;
    Ok(Stored {
        algorithm: format!("{PREFIX}{}", parsed.scheme()),
        text: format!("{spec}\n{hash}"),
    })
}

/// Whether `algorithm` is an imported scheme still waiting for its first sign-in.
#[must_use]
pub fn is_legacy(algorithm: &str) -> bool {
    algorithm.starts_with(PREFIX)
}

/// Checks `password` against a stored imported hash (not [`IDP`]).
///
/// # Errors
/// [`LegacyHashError`] for a stored text outside its format.
pub fn verify(algorithm: &str, text: &str, password: &Password) -> Result<bool, LegacyHashError> {
    if algorithm == ARGON2 {
        let h = PasswordHash::new(text).map_err(|_| LegacyHashError::Malformed)?;
        if !argon2_bounded(&h) {
            return Err(LegacyHashError::Bound);
        }
        return match Argon2::default().verify_password(password.bytes(), &h) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
            Err(_) => Err(LegacyHashError::Malformed),
        };
    }
    let (spec, hash) = text.split_once('\n').ok_or(LegacyHashError::Malformed)?;
    let parsed = LegacyHash::parse(hash)?;
    if format!("{PREFIX}{}", parsed.scheme()) != algorithm {
        return Err(LegacyHashError::Malformed);
    }
    parsed.verify(&Transform::parse(spec)?, password.bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> Password {
        Password::presented(s).unwrap()
    }

    // TN-85, CR-37, OP-153 m.11 (h)
    #[test]
    fn imported_hashes_are_classified_and_checked_by_their_scheme() {
        let bcrypt = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        let s = classify(bcrypt, None).unwrap();
        assert_eq!(s.algorithm, "legacy-bcrypt");
        assert!(is_legacy(&s.algorithm));
        assert!(verify(&s.algorithm, &s.text, &pw("U*U")).unwrap());
        assert!(!verify(&s.algorithm, &s.text, &pw("U*U*")).unwrap());
        assert!(matches!(
            classify("plainhex", None),
            Err(ImportRejected::Hash(LegacyHashError::Unknown))
        ));
        assert!(matches!(
            classify(bcrypt, Some("prehash=rot13")),
            Err(ImportRejected::Hash(LegacyHashError::Transform))
        ));
        assert!(verify("legacy-scrypt", &s.text, &pw("U*U")).is_err());
    }

    // CR-37, OP-33
    #[test]
    fn argon2_strings_keep_their_family_and_bounds() {
        use argon2::PasswordHasher as _;
        let params = argon2::Params::new(8, 1, 1, None).unwrap();
        let salt = b"0123456789abcdef";
        let id = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params.clone(),
        );
        let i = Argon2::new(argon2::Algorithm::Argon2i, argon2::Version::V0x13, params);
        let h_id = id
            .hash_password_with_salt(b"hunter22", salt)
            .unwrap()
            .to_string();
        let h_i = i
            .hash_password_with_salt(b"hunter22", salt)
            .unwrap()
            .to_string();
        assert_eq!(classify(&h_id, None).unwrap().algorithm, ALGORITHM);
        let s = classify(&h_i, None).unwrap();
        assert_eq!(s.algorithm, ARGON2);
        assert!(verify(ARGON2, &s.text, &pw("hunter22")).unwrap());
        assert!(!verify(ARGON2, &s.text, &pw("hunter23")).unwrap());
        assert_eq!(
            classify(&h_i, Some("prehash=sha256-hex")),
            Err(ImportRejected::Argon2Transform)
        );
        let huge = h_id.replace("m=8", "m=4194304");
        assert_eq!(
            classify(&huge, None),
            Err(ImportRejected::Hash(LegacyHashError::Bound))
        );
    }
}
