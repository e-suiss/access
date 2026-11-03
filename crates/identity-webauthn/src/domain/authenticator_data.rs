//! Authenticator data (WebAuthn L3 §6.1), parsed within the WebAuthn input limit (CR-10).

use access_parse::cbor::{Item, Limits, MAX_INPUT, decode, decode_prefix};

use super::Rejection;
use super::cose::CoseKey;
use super::ids::{Aaguid, CredentialId};

/// The flags byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Backup eligible.
    pub const BE: u8 = 0x08;
    /// Backup state.
    pub const BS: u8 = 0x10;
    /// Attested credential data included.
    pub const AT: u8 = 0x40;
    /// Extension data included.
    pub const ED: u8 = 0x80;

    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// UP.
    #[must_use]
    pub const fn user_present(self) -> bool {
        self.has(Self::UP)
    }

    /// UV.
    #[must_use]
    pub const fn user_verified(self) -> bool {
        self.has(Self::UV)
    }

    /// BE.
    #[must_use]
    pub const fn backup_eligible(self) -> bool {
        self.has(Self::BE)
    }

    /// BS.
    #[must_use]
    pub const fn backed_up(self) -> bool {
        self.has(Self::BS)
    }

    /// IDI-5: BE = 0 with BS = 1 is invalid.
    #[must_use]
    pub const fn backup_consistent(self) -> bool {
        self.backup_eligible() || !self.backed_up()
    }
}

/// Attested credential data from a registration.
#[derive(Clone)]
pub struct AttestedCredential<'a> {
    /// Authenticator model hint.
    pub aaguid: Aaguid,
    /// The new credential's ID.
    pub credential_id: CredentialId,
    /// The `COSE_Key` bytes as the authenticator encoded them.
    pub public_key_raw: &'a [u8],
    /// The parsed key.
    pub public_key: CoseKey,
}

/// Authenticator extension outputs Access reads; others are ignored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extensions {
    /// `credProtect` level, 1–3.
    pub cred_protect: Option<u8>,
}

/// Parsed authenticator data.
#[derive(Clone)]
pub struct AuthenticatorData<'a> {
    /// The raw bytes, the first half of the signed message.
    pub raw: &'a [u8],
    /// SHA-256 of the RP ID the authenticator used.
    pub rp_id_hash: [u8; 32],
    /// Flags.
    pub flags: Flags,
    /// Signature counter.
    pub sign_count: u32,
    /// Present when AT is set.
    pub attested: Option<AttestedCredential<'a>>,
    /// Extension outputs when ED is set.
    pub extensions: Extensions,
}

fn split(input: &[u8], n: usize) -> Result<(&[u8], &[u8]), Rejection> {
    if input.len() < n {
        Err(Rejection::AuthenticatorData)
    } else {
        Ok(input.split_at(n))
    }
}

fn extensions(item: &Item<'_>) -> Result<Extensions, Rejection> {
    let map = item.as_map().ok_or(Rejection::AuthenticatorData)?;
    let mut out = Extensions::default();
    for (key, value) in map {
        if key.as_text() == Some("credProtect") {
            let level = value
                .as_i64()
                .and_then(|v| u8::try_from(v).ok())
                .filter(|v| (1..=3).contains(v))
                .ok_or(Rejection::AuthenticatorData)?;
            out.cred_protect = Some(level);
        }
    }
    Ok(out)
}

impl<'a> AuthenticatorData<'a> {
    /// Parses authenticator data; nothing may follow the declared parts.
    ///
    /// # Errors
    /// [`Rejection`].
    pub fn parse(raw: &'a [u8]) -> Result<Self, Rejection> {
        if raw.len() > MAX_INPUT {
            return Err(Rejection::AuthenticatorData);
        }
        let (hash, rest) = split(raw, 32)?;
        let (flags, rest) = split(rest, 1)?;
        let (count, mut rest) = split(rest, 4)?;
        let rp_id_hash = <[u8; 32]>::try_from(hash).map_err(|_| Rejection::AuthenticatorData)?;
        let flags = Flags(*flags.first().ok_or(Rejection::AuthenticatorData)?);
        let sign_count = u32::from_be_bytes(
            <[u8; 4]>::try_from(count).map_err(|_| Rejection::AuthenticatorData)?,
        );
        let attested = if flags.has(Flags::AT) {
            let (aaguid, after) = split(rest, 16)?;
            let (len, after) = split(after, 2)?;
            let len = usize::from(u16::from_be_bytes(
                <[u8; 2]>::try_from(len).map_err(|_| Rejection::AuthenticatorData)?,
            ));
            let (id, after) = split(after, len)?;
            let credential_id = CredentialId::new(id).ok_or(Rejection::AttestedCredential)?;
            let (key_item, used) = decode_prefix(after, Limits::CEILING)?;
            let (key_raw, after) = split(after, used)?;
            let public_key = CoseKey::from_item(&key_item)?;
            rest = after;
            Some(AttestedCredential {
                aaguid: Aaguid(
                    <[u8; 16]>::try_from(aaguid).map_err(|_| Rejection::AuthenticatorData)?,
                ),
                credential_id,
                public_key_raw: key_raw,
                public_key,
            })
        } else {
            None
        };
        let extensions = if flags.has(Flags::ED) {
            let item = decode(rest, Limits::CEILING)?;
            rest = &[];
            extensions(&item)?
        } else {
            Extensions::default()
        };
        if !rest.is_empty() {
            return Err(Rejection::AuthenticatorData);
        }
        Ok(Self {
            raw,
            rp_id_hash,
            flags,
            sign_count,
            attested,
            extensions,
        })
    }
}
