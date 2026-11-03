//! The credential envelope (OP-42, OP-135, OP-145): realm KEK → subject DEK → one DEK per
//! credential secret. Shredding the subject DEK makes every credential below it unreadable.

use std::fmt::Write as _;

use access_crypto::Secret;
use access_store::accounts::{SealedSecret, SubjectRow};
use suiss_crypto::envelope::{Dek, DekKek, Kek, Sealed, open_body, seal_body};

use crate::AccountError;
use crate::app::Realm;

const CONTEXT: &[u8] = b"access/credential/v1\0";

/// The id stored as `kek_id` next to keys the subject's DEK wraps.
#[must_use]
pub fn subject_dek_id(subject: &[u8; 16]) -> String {
    subject.iter().fold(String::from("sub-dek:"), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn context(realm: &Realm<'_>, subject: &[u8; 16], kind: &str) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.extend_from_slice(realm.tenant.as_bytes());
    c.extend_from_slice(realm.realm.as_bytes());
    c.extend_from_slice(subject);
    c.extend_from_slice(kind.as_bytes());
    c
}

/// A fresh subject DEK and its form wrapped by the realm KEK.
///
/// # Errors
/// [`AccountError::Envelope`].
pub fn new_subject_key(realm: &Realm<'_>) -> Result<Vec<u8>, AccountError> {
    let dek = Dek::generate()?;
    Ok(realm.kek.wrap(&dek)?)
}

/// The subject's DEK, unwrapped by the realm KEK that wrapped it.
///
/// # Errors
/// [`AccountError::Envelope`]; [`AccountError::Corrupt`] when another KEK wrapped it or it
/// was shredded.
pub fn subject_key(realm: &Realm<'_>, row: &SubjectRow) -> Result<Dek, AccountError> {
    if row.kek_id != realm.kek.id() {
        return Err(AccountError::Corrupt);
    }
    let wrapped = row.wrapped_dek.as_deref().ok_or(AccountError::Corrupt)?;
    Ok(realm.kek.unwrap(wrapped)?)
}

/// Seals a credential secret under its own DEK, wrapped by the subject's DEK.
///
/// # Errors
/// [`AccountError::Envelope`].
pub fn seal(
    realm: &Realm<'_>,
    subject_dek: &Dek,
    subject: &[u8; 16],
    kind: &str,
    secret: &[u8],
) -> Result<SealedSecret, AccountError> {
    let id = subject_dek_id(subject);
    let dek = Dek::generate()?;
    let wrapped_dek = DekKek::new(&id, subject_dek).wrap(&dek)?;
    let s = seal_body(dek, &context(realm, subject, kind), secret)?;
    Ok(SealedSecret {
        kek_id: id,
        wrapped_dek,
        nonce: s.nonce,
        ciphertext: s.ciphertext,
        pepper_version: None,
    })
}

/// Opens a sealed credential secret as UTF-8.
///
/// # Errors
/// [`AccountError::Envelope`]; [`AccountError::Corrupt`] for a foreign wrapping key or
/// non-UTF-8 content.
pub fn open(
    realm: &Realm<'_>,
    subject_dek: &Dek,
    subject: &[u8; 16],
    kind: &str,
    sealed: &SealedSecret,
) -> Result<Secret<String>, AccountError> {
    let id = subject_dek_id(subject);
    if sealed.kek_id != id {
        return Err(AccountError::Corrupt);
    }
    let dek = DekKek::new(&id, subject_dek).unwrap(&sealed.wrapped_dek)?;
    let plain = open_body(
        &dek,
        &context(realm, subject, kind),
        &Sealed {
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext.clone(),
        },
    )?;
    let text = core::str::from_utf8(&plain).map_err(|_| AccountError::Corrupt)?;
    Ok(Secret::new(text.to_owned()))
}
