//! Opaque external identifiers (§5.3, §12.1.3, OP-11, MD-18, OP-137): the internal `UUIDv7` is
//! one AES-256 block, so a keyed permutation of it hides its time and order and needs no lookup
//! table. The text form is a type prefix and 26 lower-case Crockford base32 characters.
//!
//! Obscurity, not authentication: a forged id decodes to some UUID that a scoped lookup does
//! not find.

use aws_lc_rs::cipher::{AES_256, DecryptingKey, EncryptingKey, UnboundCipherKey};

use crate::dit::DitGuard;
use crate::secret::Secret;

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
const LEN: usize = 26;

/// Why a text id was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpaqueIdError {
    /// Not this type's prefix.
    #[error("prefix")]
    Prefix,
    /// Wrong length, a character outside the alphabet, or a non-canonical spelling.
    #[error("encoding")]
    Encoding,
    /// The cipher failed.
    #[error("cipher")]
    Cipher,
}

/// The cell's id key; the HSM keeps it in production (OP-94).
pub struct IdKey(Secret<[u8; 32]>);

impl IdKey {
    /// Wraps key material.
    #[must_use]
    pub fn new(key: Secret<[u8; 32]>) -> Self {
        Self(key)
    }

    fn block(&self, id: [u8; 16], forward: bool) -> Result<[u8; 16], OpaqueIdError> {
        // CR-39 m.6
        let _dit = DitGuard::new();
        let unbound =
            || UnboundCipherKey::new(&AES_256, self.0.expose()).map_err(|_| OpaqueIdError::Cipher);
        let mut block = id;
        if forward {
            EncryptingKey::ecb(unbound()?)
                .and_then(|k| k.encrypt(&mut block))
                .map_err(|_| OpaqueIdError::Cipher)?;
        } else {
            DecryptingKey::ecb(unbound()?)
                .and_then(|k| {
                    k.decrypt(&mut block, aws_lc_rs::cipher::DecryptionContext::None)
                        .map(drop)
                })
                .map_err(|_| OpaqueIdError::Cipher)?;
        }
        Ok(block)
    }

    /// `prefix` `_` and the permuted id.
    ///
    /// # Errors
    /// [`OpaqueIdError`].
    pub fn encode(&self, prefix: &str, id: [u8; 16]) -> Result<String, OpaqueIdError> {
        check_prefix(prefix)?;
        let v = u128::from_be_bytes(self.block(id, true)?);
        let mut out = String::with_capacity(prefix.len().saturating_add(1).saturating_add(LEN));
        out.push_str(prefix);
        out.push('_');
        for i in (0..LEN).rev() {
            let shift = u32::try_from(i.saturating_mul(5)).map_err(|_| OpaqueIdError::Encoding)?;
            let digit = usize::try_from((v.checked_shr(shift).unwrap_or(0)) & 31)
                .map_err(|_| OpaqueIdError::Encoding)?;
            out.push(char::from(
                *ALPHABET.get(digit).ok_or(OpaqueIdError::Encoding)?,
            ));
        }
        Ok(out)
    }

    /// The internal id of `text`, which must carry `prefix`.
    ///
    /// # Errors
    /// [`OpaqueIdError`].
    pub fn decode(&self, prefix: &str, text: &str) -> Result<[u8; 16], OpaqueIdError> {
        check_prefix(prefix)?;
        let body = text
            .strip_prefix(prefix)
            .and_then(|t| t.strip_prefix('_'))
            .ok_or(OpaqueIdError::Prefix)?;
        if body.len() != LEN {
            return Err(OpaqueIdError::Encoding);
        }
        let mut v: u128 = 0;
        for (i, c) in body.bytes().enumerate() {
            let digit = ALPHABET
                .iter()
                .position(|a| *a == c)
                .ok_or(OpaqueIdError::Encoding)?;
            // 26 × 5 = 130 bits: the first character carries only 3 (canonical form)
            if i == 0 && digit > 7 {
                return Err(OpaqueIdError::Encoding);
            }
            v = v.checked_shl(5).ok_or(OpaqueIdError::Encoding)?
                | u128::try_from(digit).map_err(|_| OpaqueIdError::Encoding)?;
        }
        self.block(v.to_be_bytes(), false)
    }
}

fn check_prefix(prefix: &str) -> Result<(), OpaqueIdError> {
    if (2..=4).contains(&prefix.len()) && prefix.bytes().all(|b| b.is_ascii_lowercase()) {
        Ok(())
    } else {
        Err(OpaqueIdError::Prefix)
    }
}

#[cfg(test)]
mod tests;
