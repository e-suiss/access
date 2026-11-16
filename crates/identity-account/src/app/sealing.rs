//! The credential envelope (OP-42, OP-135, OP-145): environment KEK → subject DEK → one DEK per
//! credential secret. Shredding the subject DEK makes every credential below it unreadable.

use std::fmt::Write as _;

use access_crypto::Secret;
use access_store::accounts::{SealedSecret, SubjectRow};
use suiss_crypto::envelope::{Dek, DekKek, Kek, Sealed, open_body, seal_body};
use zeroize::Zeroizing;

use crate::AccountError;
use crate::app::Environment;

const CONTEXT: &[u8] = b"access/credential/v1\0";

const PEPPER_CONTEXT: &[u8] = b"access/password-pepper/v1\0";

const PASSWORD: &str = crate::app::accounts::PASSWORD;

/// The id stored as `kek_id` next to keys the subject's DEK wraps.
#[must_use]
pub fn subject_dek_id(subject: &[u8; 16]) -> String {
    subject.iter().fold(String::from("sub-dek:"), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn context(environment: &Environment<'_>, subject: &[u8; 16], kind: &str) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.extend_from_slice(environment.tenant.as_bytes());
    c.extend_from_slice(environment.environment.as_bytes());
    c.extend_from_slice(subject);
    c.extend_from_slice(kind.as_bytes());
    c
}

/// A fresh subject DEK and its form wrapped by the environment KEK.
///
/// # Errors
/// [`AccountError::Envelope`].
pub fn new_subject_key(environment: &Environment<'_>) -> Result<Vec<u8>, AccountError> {
    let dek = Dek::generate()?;
    Ok(environment.kek.wrap(&dek)?)
}

/// The subject's DEK, unwrapped by the environment KEK that wrapped it.
///
/// # Errors
/// [`AccountError::Envelope`]; [`AccountError::Corrupt`] when another KEK wrapped it or it
/// was shredded.
pub fn subject_key(environment: &Environment<'_>, row: &SubjectRow) -> Result<Dek, AccountError> {
    if !environment.kek.opens(&row.kek_id) {
        return Err(AccountError::Corrupt);
    }
    let wrapped = row.wrapped_dek.as_deref().ok_or(AccountError::Corrupt)?;
    Ok(environment.kek.unwrap(wrapped)?)
}

/// Seals a credential secret under its own DEK, wrapped by the subject's DEK.
///
/// # Errors
/// [`AccountError::Envelope`].
pub fn seal(
    environment: &Environment<'_>,
    subject_dek: &Dek,
    subject: &[u8; 16],
    kind: &str,
    secret: &[u8],
) -> Result<SealedSecret, AccountError> {
    let id = subject_dek_id(subject);
    let dek = Dek::generate()?;
    let wrapped_dek = DekKek::new(&id, subject_dek).wrap(&dek)?;
    let s = seal_body(dek, &context(environment, subject, kind), secret)?;
    Ok(SealedSecret {
        kek_id: id,
        wrapped_dek,
        nonce: s.nonce,
        ciphertext: s.ciphertext,
        pepper_version: None,
    })
}

fn pepper_context(environment: &Environment<'_>, subject: &[u8; 16]) -> Vec<u8> {
    let mut c = PEPPER_CONTEXT.to_vec();
    c.extend_from_slice(&context(environment, subject, PASSWORD));
    c
}

/// Seals a password hash: the environment's pepper over the PHC string first, then the credential
/// envelope, with the pepper version beside it (CR-37, OP-150 m.3 (f)). There is no unpeppered
/// path: an environment KEK without its pepper refuses (TI-9).
///
/// # Errors
/// [`AccountError::Envelope`].
pub fn seal_password(
    environment: &Environment<'_>,
    subject_dek: &Dek,
    subject: &[u8; 16],
    phc: &[u8],
) -> Result<SealedSecret, AccountError> {
    let (version, peppered) = environment
        .kek
        .pepper(&pepper_context(environment, subject), phc)?;
    let mut sealed = seal(environment, subject_dek, subject, PASSWORD, &peppered)?;
    sealed.pepper_version = Some(i16::try_from(version).map_err(|_| AccountError::Corrupt)?);
    Ok(sealed)
}

/// Opens a sealed password hash; the flag says it carries no pepper yet and is resealed at the
/// next sign-in (CR-37 rehash on login).
///
/// # Errors
/// [`AccountError::Envelope`]; [`AccountError::Corrupt`].
pub fn open_password(
    environment: &Environment<'_>,
    subject_dek: &Dek,
    subject: &[u8; 16],
    sealed: &SealedSecret,
) -> Result<(Secret<String>, bool), AccountError> {
    let Some(version) = sealed.pepper_version else {
        return Ok((
            open(environment, subject_dek, subject, PASSWORD, sealed)?,
            true,
        ));
    };
    let version = u16::try_from(version).map_err(|_| AccountError::Corrupt)?;
    let peppered = open_bytes(environment, subject_dek, subject, PASSWORD, sealed)?;
    let plain =
        environment
            .kek
            .unpepper(version, &pepper_context(environment, subject), &peppered)?;
    let text = core::str::from_utf8(&plain).map_err(|_| AccountError::Corrupt)?;
    Ok((Secret::new(text.to_owned()), false))
}

/// Opens a sealed credential secret as UTF-8.
///
/// # Errors
/// [`AccountError::Envelope`]; [`AccountError::Corrupt`] for a foreign wrapping key or
/// non-UTF-8 content.
pub fn open(
    environment: &Environment<'_>,
    subject_dek: &Dek,
    subject: &[u8; 16],
    kind: &str,
    sealed: &SealedSecret,
) -> Result<Secret<String>, AccountError> {
    let plain = open_bytes(environment, subject_dek, subject, kind, sealed)?;
    let text = core::str::from_utf8(&plain).map_err(|_| AccountError::Corrupt)?;
    Ok(Secret::new(text.to_owned()))
}

fn open_bytes(
    environment: &Environment<'_>,
    subject_dek: &Dek,
    subject: &[u8; 16],
    kind: &str,
    sealed: &SealedSecret,
) -> Result<Zeroizing<Vec<u8>>, AccountError> {
    let id = subject_dek_id(subject);
    if sealed.kek_id != id {
        return Err(AccountError::Corrupt);
    }
    let dek = DekKek::new(&id, subject_dek).unwrap(&sealed.wrapped_dek)?;
    Ok(open_body(
        &dek,
        &context(environment, subject, kind),
        &Sealed {
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext.clone(),
        },
    )?)
}
