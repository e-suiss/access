//! The person's browser profile and microVM disk key in the cloud executor (E50 (1), E52,
//! E61 (2), (4), OP-156 m.3 (w)). The profile is sealed under the person's own
//! `one_browser_profile` DEK, which reaches the microVM only while the person is online or under
//! a cloud key permission; the operator and the host hold no key that opens it. The disk key is
//! random per microVM and kept only wrapped under that DEK; when the Mandate or the task ends it
//! is destroyed, and the profile with it. A profile opens only for the Exercise its task runs.

use suiss_crypto::envelope::{Dek, Sealed, Sealer};
use suiss_crypto::secret::Secret;

use super::browser::Release;

/// Why a profile or disk key does not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// Not the person's DEK, not their profile, or the ciphertext was changed.
    #[error("executor-profile")]
    Open,
    /// The randomness or the cipher failed.
    #[error("executor-profile-seal")]
    Seal,
    /// The disk key was destroyed.
    #[error("executor-disk-key-destroyed")]
    Destroyed,
}

/// A person's sealed browser profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedProfile {
    /// Whose it is.
    pub person: [u8; 16],
    /// The profile under the person's DEK.
    pub sealed: Sealed,
}

fn context(label: &str, person: &[u8; 16]) -> Vec<u8> {
    let mut c = label.as_bytes().to_vec();
    c.push(0);
    c.extend_from_slice(person);
    c
}

fn sealer(dek: &Secret<[u8; 32]>) -> Sealer {
    Sealer::new(Dek::from_secret(dek.clone()), 0)
}

/// Seals `profile` of `person` under their `one_browser_profile` DEK.
///
/// # Errors
/// [`ProfileError::Seal`].
pub fn seal(
    person: [u8; 16],
    dek: &Secret<[u8; 32]>,
    profile: &[u8],
) -> Result<SealedProfile, ProfileError> {
    let sealed = sealer(dek)
        .seal(
            &context("access/executor/browser-profile/v1", &person),
            profile,
        )
        .map_err(|_| ProfileError::Seal)?;
    Ok(SealedProfile { person, sealed })
}

/// Opens `profile` for the task `release` names: there is no other way to open one (E50 (3)).
///
/// # Errors
/// [`ProfileError::Open`].
pub fn open(
    profile: &SealedProfile,
    dek: &Secret<[u8; 32]>,
    _release: &Release,
) -> Result<Secret<Vec<u8>>, ProfileError> {
    let opened = sealer(dek)
        .open(
            &context("access/executor/browser-profile/v1", &profile.person),
            &profile.sealed,
        )
        .map_err(|_| ProfileError::Open)?;
    Ok(Secret::new(opened.to_vec()))
}

/// A microVM's disk key, kept only wrapped under the person's DEK (E61 (2)).
pub struct DiskKey {
    person: [u8; 16],
    wrapped: Option<Sealed>,
}

impl DiskKey {
    /// A fresh random disk key for `person`'s microVM, wrapped under their DEK.
    ///
    /// # Errors
    /// [`ProfileError::Seal`].
    pub fn generate(person: [u8; 16], dek: &Secret<[u8; 32]>) -> Result<Self, ProfileError> {
        let key = Dek::generate().map_err(|_| ProfileError::Seal)?;
        let wrapped = sealer(dek)
            .seal(
                &context("access/executor/disk-key/v1", &person),
                key.secret().expose(),
            )
            .map_err(|_| ProfileError::Seal)?;
        Ok(Self {
            person,
            wrapped: Some(wrapped),
        })
    }

    /// The disk key, unwrapped with the person's DEK.
    ///
    /// # Errors
    /// [`ProfileError`].
    pub fn unwrap_with(&self, dek: &Secret<[u8; 32]>) -> Result<Secret<[u8; 32]>, ProfileError> {
        let wrapped = self.wrapped.as_ref().ok_or(ProfileError::Destroyed)?;
        let bytes = sealer(dek)
            .open(
                &context("access/executor/disk-key/v1", &self.person),
                wrapped,
            )
            .map_err(|_| ProfileError::Open)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Secret::new)
            .map_err(|_| ProfileError::Open)
    }

    /// Destroys the wrapped key when the Mandate or the task ends (E61 (4)); nothing can open
    /// the disk afterwards.
    pub fn shred(&mut self) {
        self.wrapped = None;
    }

    /// Whether it was destroyed.
    #[must_use]
    pub const fn shredded(&self) -> bool {
        self.wrapped.is_none()
    }
}
