//! The OpenSSH user certificate `ssh-ed25519-cert-v01@openssh.com` (OpenSSH `PROTOCOL.certkeys`),
//! our own small encoder (OP-156 m.3 (o), (z)): the fields to sign, the signed certificate and
//! the line `ssh-keygen -L` and `sshd` read. Critical options and extensions are written in
//! lexical order, each option's data a `string` inside the option's `string`.

use std::collections::BTreeSet;

use suiss_crypto::note::{base64_decode, base64_encode};

use super::key::{ED25519, Ed25519Public, signature_blob};
use super::wire::{Reader, Writer, packed, unpacked};
use crate::SshError;

/// The certificate key type.
pub const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";

/// `SSH2_CERT_TYPE_USER`.
pub const USER_CERT: u32 = 1;

/// Most principals one certificate names (OpenSSH `SSHKEY_CERT_MAX_PRINCIPALS`).
pub const MAX_PRINCIPALS: usize = 256;

/// Longest principal, in bytes (`ssh-cert.cddl`).
pub const MAX_PRINCIPAL: usize = 64;

/// Longest key identifier, in bytes (`ssh-cert.cddl`).
pub const MAX_KEY_ID: usize = 128;

/// Longest `force-command`, in bytes (`ssh-cert.cddl`).
pub const MAX_COMMAND: usize = 4096;

/// Most `source-address` entries (`ssh-cert.cddl` sizes each at most 64 bytes).
pub const MAX_SOURCES: usize = 32;

/// The `force-command` critical option.
pub const FORCE_COMMAND: &str = "force-command";

/// The `source-address` critical option.
pub const SOURCE_ADDRESS: &str = "source-address";

/// A certificate extension a Grant may permit (`ssh-cert.cddl` `ssh-extension`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Extension {
    /// `permit-X11-forwarding`.
    X11Forwarding,
    /// `permit-agent-forwarding`.
    AgentForwarding,
    /// `permit-port-forwarding`.
    PortForwarding,
    /// `permit-pty`.
    Pty,
    /// `permit-user-rc`.
    UserRc,
}

impl Extension {
    /// Every extension, in the lexical order of their names.
    pub const ALL: [Self; 5] = [
        Self::X11Forwarding,
        Self::AgentForwarding,
        Self::PortForwarding,
        Self::Pty,
        Self::UserRc,
    ];

    /// The extension's name on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X11Forwarding => "permit-X11-forwarding",
            Self::AgentForwarding => "permit-agent-forwarding",
            Self::PortForwarding => "permit-port-forwarding",
            Self::Pty => "permit-pty",
            Self::UserRc => "permit-user-rc",
        }
    }

    /// The Grant parameter that permits it (`ssh.login`).
    #[must_use]
    pub const fn param(self) -> &'static str {
        match self {
            Self::X11Forwarding => "permit_x11_forwarding",
            Self::AgentForwarding => "permit_agent_forwarding",
            Self::PortForwarding => "permit_port_forwarding",
            Self::Pty => "permit_pty",
            Self::UserRc => "permit_user_rc",
        }
    }

    /// The extension of a wire name.
    #[must_use]
    pub fn of_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.name() == name)
    }
}

/// Whether `p` may be a principal: 1 to 64 bytes of letters, digits, `.`, `_` and `-`, not
/// starting with `-` (a server user name; no `,` that `AuthorizedPrincipalsFile` would split).
#[must_use]
pub fn principal_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PRINCIPAL
        && !p.starts_with('-')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `c` may be a `force-command`: 1 to 4096 bytes, no control characters.
#[must_use]
pub fn command_ok(c: &str) -> bool {
    !c.is_empty() && c.len() <= MAX_COMMAND && !c.chars().any(char::is_control)
}

/// Whether `a` is one `source-address` entry: an IPv4 or IPv6 address, optionally with a
/// prefix length within the family's width.
#[must_use]
pub fn source_ok(a: &str) -> bool {
    if a.is_empty() || a.len() > 64 {
        return false;
    }
    let (addr, bits) = match a.split_once('/') {
        Some((addr, bits)) => (addr, Some(bits)),
        None => (a, None),
    };
    let Ok(ip) = addr.parse::<core::net::IpAddr>() else {
        return false;
    };
    let width = if ip.is_ipv4() { 32 } else { 128 };
    bits.is_none_or(|b| {
        !b.is_empty()
            && b.bytes().all(|c| c.is_ascii_digit())
            && b.len() <= 3
            && b.parse::<u8>().is_ok_and(|n| n <= width)
    })
}

/// What a certificate says, before the CA signs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    /// 32 bytes from the RNG.
    pub nonce: [u8; 32],
    /// The holder's key.
    pub key: Ed25519Public,
    /// 64 bits from the RNG, never 0 (a KRL cannot name serial 0).
    pub serial: u64,
    /// The key identifier: the projection's identifier.
    pub key_id: String,
    /// The principals, in order, without repeats.
    pub principals: BTreeSet<String>,
    /// Unix seconds.
    pub valid_after: u64,
    /// Unix seconds.
    pub valid_before: u64,
    /// The `force-command` option.
    pub force_command: Option<String>,
    /// The `source-address` option's entries.
    pub source_address: BTreeSet<String>,
    /// The extensions.
    pub extensions: BTreeSet<Extension>,
    /// The CA key that signs it.
    pub ca: Ed25519Public,
}

fn option(w: &mut Writer, name: &str, value: &[u8]) -> Result<(), SshError> {
    let mut inner = Writer::new();
    inner.string(value)?;
    w.string(name.as_bytes())?.string(inner.bytes())?;
    Ok(())
}

impl Fields {
    /// Whether the fields are inside the encoder's limits.
    ///
    /// # Errors
    /// [`SshError::Fields`].
    pub fn check(&self) -> Result<(), SshError> {
        let ok = self.serial != 0
            && !self.key_id.is_empty()
            && self.key_id.len() <= MAX_KEY_ID
            && !self.key_id.chars().any(char::is_control)
            && !self.principals.is_empty()
            && self.principals.len() <= MAX_PRINCIPALS
            && self.principals.iter().all(|p| principal_ok(p))
            && self.valid_after < self.valid_before
            && self.force_command.as_deref().is_none_or(command_ok)
            && self.source_address.len() <= MAX_SOURCES
            && self.source_address.iter().all(|a| source_ok(a));
        if ok { Ok(()) } else { Err(SshError::Fields) }
    }

    /// The critical options, in lexical order.
    fn critical(&self) -> Result<Vec<u8>, SshError> {
        let mut w = Writer::new();
        if let Some(c) = &self.force_command {
            option(&mut w, FORCE_COMMAND, c.as_bytes())?;
        }
        if !self.source_address.is_empty() {
            let joined = self
                .source_address
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",");
            option(&mut w, SOURCE_ADDRESS, joined.as_bytes())?;
        }
        Ok(w.finish())
    }

    /// The extensions, in lexical order, each with empty data.
    fn extensions_blob(&self) -> Result<Vec<u8>, SshError> {
        let mut w = Writer::new();
        for e in &self.extensions {
            w.string(e.name().as_bytes())?.string(&[])?;
        }
        Ok(w.finish())
    }

    /// The bytes the CA signs: every field through the signature key.
    ///
    /// # Errors
    /// [`SshError`].
    pub fn to_be_signed(&self) -> Result<Vec<u8>, SshError> {
        self.check()?;
        let principals = packed(self.principals.iter().map(String::as_bytes))?;
        let mut w = Writer::new();
        w.string(CERT_TYPE.as_bytes())?
            .string(&self.nonce)?
            .string(&self.key.0)?
            .u64(self.serial)
            .u32(USER_CERT)
            .string(self.key_id.as_bytes())?
            .string(&principals)?
            .u64(self.valid_after)
            .u64(self.valid_before)
            .string(&self.critical()?)?
            .string(&self.extensions_blob()?)?
            .string(&[])?
            .string(&self.ca.blob())?;
        Ok(w.finish())
    }

    /// The certificate: the signed bytes followed by the CA's signature over them.
    ///
    /// # Errors
    /// [`SshError`].
    pub fn certificate(&self, signature: &[u8; 64]) -> Result<Certificate, SshError> {
        let mut blob = self.to_be_signed()?;
        let mut w = Writer::new();
        w.string(&signature_blob(signature)?)?;
        blob.extend_from_slice(w.bytes());
        Ok(Certificate(blob))
    }
}

/// A signed certificate blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate(pub Vec<u8>);

impl Certificate {
    /// The `*-cert.pub` line: `ssh-ed25519-cert-v01@openssh.com <base64> <comment>`.
    #[must_use]
    pub fn line(&self, comment: &str) -> String {
        let b = base64_encode(&self.0);
        if comment.is_empty() {
            format!("{CERT_TYPE} {b}")
        } else {
            format!("{CERT_TYPE} {b} {comment}")
        }
    }

    /// The certificate of a `*-cert.pub` line.
    ///
    /// # Errors
    /// [`SshError::Malformed`].
    pub fn of_line(line: &str) -> Result<Self, SshError> {
        let mut parts = line.split_ascii_whitespace();
        if parts.next() != Some(CERT_TYPE) {
            return Err(SshError::Malformed);
        }
        parts
            .next()
            .and_then(|b| base64_decode(b).ok())
            .map(Self)
            .ok_or(SshError::Malformed)
    }

    /// The fields and signature of the blob, read back; the signature is not checked.
    ///
    /// # Errors
    /// [`SshError::Malformed`]; [`SshError::TooLarge`].
    pub fn parse(&self) -> Result<(Fields, [u8; 64], usize), SshError> {
        let mut r = Reader::new(&self.0);
        if r.string(64)? != CERT_TYPE.as_bytes() {
            return Err(SshError::Malformed);
        }
        let nonce = <[u8; 32]>::try_from(r.string(64)?).map_err(|_| SshError::Malformed)?;
        let key = <[u8; 32]>::try_from(r.string(32)?).map_err(|_| SshError::Malformed)?;
        let serial = r.u64()?;
        if r.u32()? != USER_CERT {
            return Err(SshError::Malformed);
        }
        let key_id = String::from(r.text(MAX_KEY_ID)?);
        let principals = unpacked(r.string(16 * 1024)?, MAX_PRINCIPAL, MAX_PRINCIPALS)?
            .into_iter()
            .map(|p| core::str::from_utf8(p).map(String::from))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| SshError::Malformed)?;
        let valid_after = r.u64()?;
        let valid_before = r.u64()?;
        let mut force_command = None;
        let mut source_address = BTreeSet::new();
        let mut options = Reader::new(r.string(8 * 1024)?);
        while !options.is_empty() {
            let name = options.text(64)?;
            let mut data = Reader::new(options.string(MAX_COMMAND.saturating_add(4))?);
            let value = data.text(MAX_COMMAND)?;
            match name {
                FORCE_COMMAND => force_command = Some(String::from(value)),
                SOURCE_ADDRESS => source_address = value.split(',').map(String::from).collect(),
                _ => return Err(SshError::Malformed),
            }
        }
        let mut extensions = BTreeSet::new();
        let mut ext = Reader::new(r.string(1024)?);
        while !ext.is_empty() {
            let e = Extension::of_name(ext.text(64)?).ok_or(SshError::Malformed)?;
            if !ext.string(0)?.is_empty() {
                return Err(SshError::Malformed);
            }
            extensions.insert(e);
        }
        r.string(1024)?;
        let ca = Ed25519Public::of_blob(r.string(64)?)?;
        let signed = self.0.len().saturating_sub(r.rest().len());
        let mut sig = Reader::new(r.string(128)?);
        if sig.string(32)? != ED25519.as_bytes() {
            return Err(SshError::Malformed);
        }
        let signature = <[u8; 64]>::try_from(sig.string(64)?).map_err(|_| SshError::Malformed)?;
        if !sig.is_empty() || !r.is_empty() {
            return Err(SshError::Malformed);
        }
        let fields = Fields {
            nonce,
            key: Ed25519Public(key),
            serial,
            key_id,
            principals,
            valid_after,
            valid_before,
            force_command,
            source_address,
            extensions,
            ca,
        };
        Ok((fields, signature, signed))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    pub(crate) fn fields() -> Fields {
        Fields {
            nonce: [3; 32],
            key: Ed25519Public([12; 32]),
            serial: 42,
            key_id: String::from("prj_01HZX"),
            principals: BTreeSet::from([String::from("deploy"), String::from("ayse")]),
            valid_after: 1_767_225_000,
            valid_before: 1_767_253_800,
            force_command: Some(String::from("/usr/local/bin/deploy")),
            source_address: BTreeSet::from([String::from("10.0.0.0/8")]),
            extensions: BTreeSet::from([Extension::Pty, Extension::X11Forwarding]),
            ca: Ed25519Public([9; 32]),
        }
    }

    // OP-156 m.3 (o)
    #[test]
    fn a_certificate_reads_back_as_written() {
        let f = fields();
        let cert = f.certificate(&[5; 64]).unwrap();
        let (back, sig, signed) = cert.parse().unwrap();
        assert_eq!(back, f);
        assert_eq!(sig, [5; 64]);
        assert_eq!(&cert.0[..signed], f.to_be_signed().unwrap().as_slice());
        let line = cert.line("ayse@acme");
        assert_eq!(Certificate::of_line(&line).unwrap(), cert);
        let names: Vec<_> = Extension::ALL.iter().map(|e| e.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn fields_outside_the_limits_are_refused() {
        let mut f = fields();
        f.serial = 0;
        assert_eq!(f.check(), Err(SshError::Fields));
        let mut f = fields();
        f.principals.clear();
        assert_eq!(f.to_be_signed(), Err(SshError::Fields));
        let mut f = fields();
        f.principals.insert(String::from("root,admin"));
        assert_eq!(f.check(), Err(SshError::Fields));
        let mut f = fields();
        f.valid_before = f.valid_after;
        assert_eq!(f.check(), Err(SshError::Fields));
        assert!(source_ok("2001:db8::/32"));
        assert!(source_ok("192.0.2.1"));
        assert!(!source_ok("10.0.0.0/33"));
        assert!(!source_ok("example.org"));
        assert!(!command_ok("a\nb"));
        assert!(!principal_ok("-oProxyCommand"));
    }
}
