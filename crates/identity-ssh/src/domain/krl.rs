//! The OpenSSH key revocation list (OpenSSH `PROTOCOL.krl`, format version 1) the realm
//! publishes at `/realms/{slug}/ssh/krl` (OP-156 m.3 (o)): the serials of revoked certificates
//! under each CA key, and CA keys that no longer sign (replaced in an emergency, or the CA
//! turned off), so a server that pulls the list refuses every certificate they signed. The list
//! is unsigned: `sshd` reads it from a file the operator keeps current.

use std::collections::{BTreeMap, BTreeSet};

use super::key::Ed25519Public;
use super::wire::{Reader, Writer};
use crate::SshError;

/// The magic the list starts with: `SSHKRL\n\0`.
pub const MAGIC: [u8; 8] = *b"SSHKRL\n\0";

/// `KRL_FORMAT_VERSION`.
pub const FORMAT_VERSION: u32 = 1;

/// `KRL_SECTION_CERTIFICATES`.
pub const SECTION_CERTIFICATES: u8 = 1;

/// `KRL_SECTION_EXPLICIT_KEY`.
pub const SECTION_EXPLICIT_KEY: u8 = 2;

/// `KRL_SECTION_CERT_SERIAL_LIST`.
pub const CERT_SERIAL_LIST: u8 = 0x20;

/// What the list revokes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Krl {
    /// A version that only grows: the position of the newest change it reflects.
    pub version: u64,
    /// When it was made, Unix seconds.
    pub generated: u64,
    /// The revoked serials, by the CA key that signed them.
    pub serials: BTreeMap<Ed25519Public, BTreeSet<u64>>,
    /// CA keys whose every certificate is revoked.
    pub keys: BTreeSet<Ed25519Public>,
}

impl Krl {
    /// The list in its binary form; serial 0 is never written (it names no certificate).
    ///
    /// # Errors
    /// [`SshError::TooLarge`].
    pub fn encode(&self) -> Result<Vec<u8>, SshError> {
        let mut w = Writer::new();
        w.raw(&MAGIC)
            .u32(FORMAT_VERSION)
            .u64(self.version)
            .u64(self.generated)
            .u64(0)
            .string(&[])?
            .string(&[])?;
        for (ca, serials) in &self.serials {
            let listed: Vec<u64> = serials.iter().copied().filter(|s| *s != 0).collect();
            if listed.is_empty() {
                continue;
            }
            let mut list = Writer::new();
            for s in listed {
                list.u64(s);
            }
            let mut section = Writer::new();
            section
                .string(&ca.blob())?
                .string(&[])?
                .byte(CERT_SERIAL_LIST)
                .string(list.bytes())?;
            w.byte(SECTION_CERTIFICATES).string(section.bytes())?;
        }
        if !self.keys.is_empty() {
            let mut blobs: Vec<Vec<u8>> = self.keys.iter().map(Ed25519Public::blob).collect();
            blobs.sort();
            let mut section = Writer::new();
            for b in &blobs {
                section.string(b)?;
            }
            w.byte(SECTION_EXPLICIT_KEY).string(section.bytes())?;
        }
        Ok(w.finish())
    }

    /// A list read back from its binary form (the sections this encoder writes).
    ///
    /// # Errors
    /// [`SshError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, SshError> {
        let mut r = Reader::new(bytes);
        if r.raw(MAGIC.len())? != MAGIC || r.u32()? != FORMAT_VERSION {
            return Err(SshError::Malformed);
        }
        let mut out = Self {
            version: r.u64()?,
            generated: r.u64()?,
            ..Self::default()
        };
        r.u64()?;
        r.string(1024)?;
        r.string(1024)?;
        while !r.is_empty() {
            let kind = r.byte()?;
            let mut s = Reader::new(r.string(usize::MAX)?);
            match kind {
                SECTION_CERTIFICATES => {
                    let ca = Ed25519Public::of_blob(s.string(64)?)?;
                    s.string(1024)?;
                    while !s.is_empty() {
                        if s.byte()? != CERT_SERIAL_LIST {
                            return Err(SshError::Malformed);
                        }
                        let mut list = Reader::new(s.string(usize::MAX)?);
                        let entry = out.serials.entry(ca).or_default();
                        while !list.is_empty() {
                            entry.insert(list.u64()?);
                        }
                    }
                }
                SECTION_EXPLICIT_KEY => {
                    while !s.is_empty() {
                        out.keys.insert(Ed25519Public::of_blob(s.string(64)?)?);
                    }
                }
                _ => return Err(SshError::Malformed),
            }
        }
        Ok(out)
    }

    /// Whether a certificate of `ca` with `serial` is revoked.
    #[must_use]
    pub fn revokes(&self, ca: &Ed25519Public, serial: u64) -> bool {
        self.keys.contains(ca) || self.serials.get(ca).is_some_and(|s| s.contains(&serial))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    // OP-156 m.3 (o)
    #[test]
    fn a_list_reads_back_and_names_what_it_revokes() {
        let ca = Ed25519Public([1; 32]);
        let old = Ed25519Public([2; 32]);
        let krl = Krl {
            version: 7,
            generated: 1_767_225_000,
            serials: BTreeMap::from([(ca, BTreeSet::from([5, 9]))]),
            keys: BTreeSet::from([old]),
        };
        let bytes = krl.encode().unwrap();
        assert_eq!(&bytes[..8], b"SSHKRL\n\0");
        assert_eq!(Krl::decode(&bytes).unwrap(), krl);
        assert!(krl.revokes(&ca, 9));
        assert!(!krl.revokes(&ca, 10));
        assert!(krl.revokes(&old, 10));
        let empty = Krl::default().encode().unwrap();
        assert_eq!(Krl::decode(&empty).unwrap(), Krl::default());
        let zero = Krl {
            serials: BTreeMap::from([(ca, BTreeSet::from([0]))]),
            ..Krl::default()
        };
        assert_eq!(zero.encode().unwrap(), empty);
    }
}
