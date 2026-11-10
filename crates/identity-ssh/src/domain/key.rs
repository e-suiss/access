//! Ed25519 keys in OpenSSH form (RFC 8709): the public key blob, the `authorized_keys` line a
//! server's `TrustedUserCAKeys` reads, and the `SHA256:` fingerprint `ssh-keygen -l` prints.

use suiss_crypto::note::{base64_decode, base64_encode};

use super::wire::{Reader, Writer};
use crate::SshError;

/// The key type name of an Ed25519 key.
pub const ED25519: &str = "ssh-ed25519";

/// An Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519Public(pub [u8; 32]);

impl Ed25519Public {
    /// The public key blob: `string "ssh-ed25519"`, `string key`.
    #[must_use]
    pub fn blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(11).raw(ED25519.as_bytes()).u32(32).raw(&self.0);
        w.finish()
    }

    /// The key of a public key blob.
    ///
    /// # Errors
    /// [`SshError::Malformed`] for anything but one Ed25519 key.
    pub fn of_blob(blob: &[u8]) -> Result<Self, SshError> {
        let mut r = Reader::new(blob);
        if r.string(32)? != ED25519.as_bytes() {
            return Err(SshError::Malformed);
        }
        let key = <[u8; 32]>::try_from(r.string(32)?).map_err(|_| SshError::Malformed)?;
        if !r.is_empty() {
            return Err(SshError::Malformed);
        }
        Ok(Self(key))
    }

    /// The `authorized_keys` line: `ssh-ed25519 <base64 blob> <comment>`.
    #[must_use]
    pub fn line(&self, comment: &str) -> String {
        let blob = base64_encode(&self.blob());
        if comment.is_empty() {
            format!("{ED25519} {blob}")
        } else {
            format!("{ED25519} {blob} {comment}")
        }
    }

    /// The key of an `authorized_keys` line; any comment is ignored.
    ///
    /// # Errors
    /// [`SshError::Malformed`].
    pub fn of_line(line: &str) -> Result<Self, SshError> {
        let mut parts = line.split_ascii_whitespace();
        if parts.next() != Some(ED25519) {
            return Err(SshError::Malformed);
        }
        let blob = parts
            .next()
            .and_then(|b| base64_decode(b).ok())
            .ok_or(SshError::Malformed)?;
        Self::of_blob(&blob)
    }

    /// `SHA256:` and the unpadded base64 of the blob's SHA-256, as `ssh-keygen -l` prints.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = suiss_crypto::digest::sha256(&self.blob());
        format!("SHA256:{}", base64_encode(&digest).trim_end_matches('='))
    }
}

/// An Ed25519 signature in SSH form: `string "ssh-ed25519"`, `string signature`.
///
/// # Errors
/// [`SshError::TooLarge`] never in practice.
pub fn signature_blob(signature: &[u8; 64]) -> Result<Vec<u8>, SshError> {
    let mut w = Writer::new();
    w.string(ED25519.as_bytes())?.string(signature)?;
    Ok(w.finish())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn a_key_line_round_trips() {
        let k = Ed25519Public([7; 32]);
        let line = k.line("ca@acme");
        assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(line.ends_with(" ca@acme"));
        assert_eq!(Ed25519Public::of_line(&line).unwrap(), k);
        assert_eq!(Ed25519Public::of_blob(&k.blob()).unwrap(), k);
        assert!(Ed25519Public::of_line("ssh-rsa AAAA").is_err());
        assert!(k.fingerprint().starts_with("SHA256:"));
        assert!(!k.fingerprint().ends_with('='));
    }
}
