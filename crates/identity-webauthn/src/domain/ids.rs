//! Typed identifiers (OP-64).

use core::fmt;

/// An identity realm. `Debug` does not print the value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RealmId([u8; 16]);

impl fmt::Debug for RealmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealmId(..)")
    }
}

impl RealmId {
    /// From UUID bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// The UUID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A WebAuthn credential ID: 1–1023 bytes (WebAuthn L3 §5.1).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialId(Vec<u8>);

impl CredentialId {
    /// Ceiling from WebAuthn L3.
    pub const MAX_LEN: usize = 1023;

    /// The ID, or `None` if empty or longer than [`Self::MAX_LEN`].
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self> {
        (!bytes.is_empty() && bytes.len() <= Self::MAX_LEN).then(|| Self(bytes.to_vec()))
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialId({} bytes)", self.0.len())
    }
}

/// The WebAuthn `user.id`: 64 random bytes per account and realm, never derived from an
/// e-mail address or its digest (§12.3.6 invariant 10, TN-17).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserHandle([u8; 64]);

impl UserHandle {
    /// Length in bytes.
    pub const LEN: usize = 64;

    /// From stored bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 64]) -> Self {
        Self(b)
    }

    /// From a presented `userHandle`, if it has the right length.
    #[must_use]
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        <[u8; 64]>::try_from(b).ok().map(Self)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for UserHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserHandle(..)")
    }
}

/// An authenticator model identifier: a hint, never a source of trust (§10.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Aaguid(pub [u8; 16]);

impl Aaguid {
    /// The all-zero AAGUID that `none` attestation and many synced providers report.
    pub const ZERO: Self = Self([0; 16]);

    /// Parses the canonical 8-4-4-4-12 hex form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
        let dashes = text.bytes().filter(|b| *b == b'-').count();
        if hex.len() != 32 || dashes != 4 {
            return None;
        }
        let mut out = [0_u8; 16];
        for (o, pair) in out.iter_mut().zip(hex.chunks(2)) {
            let s = core::str::from_utf8(pair).ok()?;
            *o = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self(out))
    }
}
