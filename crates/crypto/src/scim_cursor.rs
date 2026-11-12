//! RFC 9865 SCIM cursors (OP-155 m.3 (g), IDP-23): the position of a list, MAC'd with a key the
//! SCIM server both issues and checks (CR-3 (b)), bound to the list that issued it and valid for
//! ten minutes. The key is drawn from the operating system's source; nothing is a literal.

use access_kernel::json::{b64url_decode, b64url_encode};
use aws_lc_rs::hmac;
use subtle::ConstantTimeEq as _;

use crate::random::{RandomError, bytes};

const CONTEXT: &[u8] = b"access/scim-cursor/v1\0";
const TAG_LEN: usize = 16;

/// Longest cursor text accepted, checked before decoding.
pub const MAX_TEXT: usize = 1024;

/// How long a cursor stays valid (OP-155 m.3 (g)).
pub const TTL_MS: u64 = 10 * 60 * 1000;

/// Why a cursor was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CursorError {
    /// Not a cursor of this list (RFC 9865 `invalidCursor`).
    #[error("invalid cursor")]
    Invalid,
    /// Older than [`TTL_MS`] (RFC 9865 `expiredCursor`).
    #[error("expired cursor")]
    Expired,
}

/// The cursor key.
pub struct CursorKey(hmac::Key);

impl CursorKey {
    /// A fresh key.
    ///
    /// # Errors
    /// [`RandomError`].
    pub fn generate() -> Result<Self, RandomError> {
        let secret = bytes::<32>()?;
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, &secret)))
    }

    fn tag(&self, list: &[u8], body: &[u8]) -> [u8; TAG_LEN] {
        let mut ctx = hmac::Context::with_key(&self.0);
        ctx.update(CONTEXT);
        let len = u32::try_from(list.len()).unwrap_or(u32::MAX);
        ctx.update(&len.to_be_bytes());
        ctx.update(list);
        ctx.update(body);
        let full = ctx.sign();
        let mut out = [0; TAG_LEN];
        out.copy_from_slice(full.as_ref().get(..TAG_LEN).unwrap_or(&[0; TAG_LEN]));
        out
    }

    /// The cursor text for `position` of the list `list`, issued at `now_ms`.
    #[must_use]
    pub fn seal(&self, list: &[u8], position: &[u8], now_ms: u64) -> String {
        let mut body = now_ms.to_be_bytes().to_vec();
        body.extend_from_slice(position);
        let tag = self.tag(list, &body);
        body.extend_from_slice(&tag);
        b64url_encode(&body)
    }

    /// The position of a cursor this key sealed for `list`, at `now_ms`.
    ///
    /// # Errors
    /// [`CursorError`].
    pub fn open(&self, list: &[u8], text: &str, now_ms: u64) -> Result<Vec<u8>, CursorError> {
        if text.len() > MAX_TEXT {
            return Err(CursorError::Invalid);
        }
        let bytes = b64url_decode(text).map_err(|_| CursorError::Invalid)?;
        let split = bytes
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(CursorError::Invalid)?;
        let (body, tag) = bytes.split_at(split);
        // CR-39 m.6
        let _dit = crate::dit::DitGuard::new();
        if !bool::from(self.tag(list, body).ct_eq(tag)) {
            return Err(CursorError::Invalid);
        }
        let (at, position) = body.split_first_chunk::<8>().ok_or(CursorError::Invalid)?;
        let issued = u64::from_be_bytes(*at);
        if now_ms < issued || now_ms.saturating_sub(issued) > TTL_MS {
            return Err(CursorError::Expired);
        }
        Ok(position.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (g), IDP-23
    #[test]
    fn a_cursor_opens_only_for_its_list_key_and_ten_minutes() {
        let k = CursorKey::generate().unwrap();
        let c = k.seal(b"users", b"after-7", 1_000);
        assert_eq!(k.open(b"users", &c, 2_000).unwrap(), b"after-7");
        assert_eq!(k.open(b"groups", &c, 2_000), Err(CursorError::Invalid));
        assert_eq!(
            k.open(b"users", &c, 1_000 + TTL_MS + 1),
            Err(CursorError::Expired)
        );
        let other = CursorKey::generate().unwrap();
        assert_eq!(other.open(b"users", &c, 2_000), Err(CursorError::Invalid));
        let mut tampered = b64url_decode(&c).unwrap();
        tampered[9] ^= 1;
        assert_eq!(
            k.open(b"users", &b64url_encode(&tampered), 2_000),
            Err(CursorError::Invalid)
        );
        assert_eq!(k.open(b"users", "!!", 2_000), Err(CursorError::Invalid));
    }
}
