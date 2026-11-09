//! Apple App Attest (§10.1.2, §12.2.1, L21, AG-31 model 1): the server checklist of
//! <https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>.
//!
//! 1. `fmt` is `apple-appattest`; `x5c` (credential certificate, then intermediate) verifies to
//!    the embedded Apple root ([`crate::domain::roots::APPLE_APP_ATTEST`]).
//! 2. The nonce extension (1.2.840.113635.100.8.2) is `SHA-256(authData ‖ clientDataHash)`.
//! 3. `SHA-256` of the credential certificate's public key is the key identifier.
//! 4. `rpIdHash` is `SHA-256` of the App ID; the counter is 0; the AAGUID is `appattest` for
//!    production or `appattestdevelop` for development, as the policy says; the credential id
//!    is the key identifier.
//!
//! The objects are read within the CBOR limits of CR-10.

use access_parse::cbor::{Item, Limits, decode};
use suiss_crypto::digest::sha256;

use crate::AttestError;
use crate::domain::der::{self, Reader};
use crate::domain::x509::{self, AnyUsage, Cert};

/// 1.2.840.113635.100.8.2, the App Attest nonce extension.
const OID_NONCE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02];

/// The AAGUID of a production attestation.
pub const AAGUID_PRODUCTION: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";

/// The AAGUID of a development attestation.
pub const AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";

/// What the policy asks of an App Attest attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy<'a> {
    /// The App ID: team identifier, a dot, and bundle identifier.
    pub app_id: &'a str,
    /// The key identifier the app sent: `SHA-256` of the public key.
    pub key_id: &'a [u8; 32],
    /// `SHA-256` of the client data, the one-time challenge Access issued included.
    pub client_data_hash: &'a [u8; 32],
    /// Whether only production attestations are accepted.
    pub production: bool,
}

/// A verified App Attest attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested {
    /// The attested public key, SEC1 uncompressed.
    pub public_key: Vec<u8>,
    /// Whether it is a production attestation.
    pub production: bool,
    /// The receipt to keep for fraud assessment.
    pub receipt: Vec<u8>,
}

fn nonce_of(cert: &Cert<'_>) -> Result<[u8; 32], AttestError> {
    let ext = cert
        .extension(OID_NONCE)
        .map_err(|_| AttestError::Format)?
        .ok_or(AttestError::Certificate)?;
    let read = || -> Result<&[u8], der::DerError> {
        let mut seq = Reader::new(Reader::new(ext.value)?.tagged(der::SEQUENCE)?)?;
        let t = seq.next_tlv()?;
        if t.tag.first != 0xa1 {
            return Err(der::DerError);
        }
        Reader::new(t.value)?.tagged(der::OCTET_STRING)
    };
    read()
        .map_err(|_| AttestError::Format)?
        .try_into()
        .map_err(|_| AttestError::Format)
}

/// Verifies the attestation object `object` to `roots` at `now_s` (Unix seconds) under
/// `policy`.
///
/// # Errors
/// [`AttestError`].
pub fn verify(
    object: &[u8],
    roots: &[&[u8]],
    policy: &Policy<'_>,
    now_s: u64,
) -> Result<Attested, AttestError> {
    let item = decode(object, Limits::CEILING).map_err(|_| AttestError::Format)?;
    if item.get_text("fmt").and_then(Item::as_text) != Some("apple-appattest") {
        return Err(AttestError::Format);
    }
    let statement = item.get_text("attStmt").ok_or(AttestError::Format)?;
    let x5c: Vec<Vec<u8>> = statement
        .get_text("x5c")
        .and_then(Item::as_array)
        .ok_or(AttestError::Format)?
        .iter()
        .map(|c| c.as_bytes().map(<[u8]>::to_vec).ok_or(AttestError::Format))
        .collect::<Result<_, _>>()?;
    let receipt = statement
        .get_text("receipt")
        .and_then(Item::as_bytes)
        .ok_or(AttestError::Format)?;
    let auth_data = item
        .get_text("authData")
        .and_then(Item::as_bytes)
        .ok_or(AttestError::Format)?;
    let (leaf, intermediates) = x5c.split_first().ok_or(AttestError::Format)?;
    x509::verify_chain(leaf, intermediates, roots, now_s, AnyUsage)
        .map_err(|_| AttestError::Chain)?;
    let cert = Cert::parse(leaf).map_err(|_| AttestError::Format)?;
    let mut message = auth_data.to_vec();
    message.extend_from_slice(policy.client_data_hash);
    if nonce_of(&cert)? != sha256(&message) {
        return Err(AttestError::Challenge);
    }
    if sha256(cert.public_key) != *policy.key_id {
        return Err(AttestError::Key);
    }
    let rp_id_hash = auth_data.get(..32).ok_or(AttestError::Format)?;
    let flags = *auth_data.get(32).ok_or(AttestError::Format)?;
    let counter = auth_data.get(33..37).ok_or(AttestError::Format)?;
    let aaguid = auth_data.get(37..53).ok_or(AttestError::Format)?;
    let len = auth_data.get(53..55).ok_or(AttestError::Format)?;
    let len = usize::from(u16::from_be_bytes([
        *len.first().ok_or(AttestError::Format)?,
        *len.get(1).ok_or(AttestError::Format)?,
    ]));
    let end = 55_usize.checked_add(len).ok_or(AttestError::Format)?;
    let credential_id = auth_data.get(55..end).ok_or(AttestError::Format)?;
    if rp_id_hash != sha256(policy.app_id.as_bytes()) {
        return Err(AttestError::Policy);
    }
    if flags & 0x40 == 0 || counter != [0, 0, 0, 0] {
        return Err(AttestError::Format);
    }
    let production = if aaguid == AAGUID_PRODUCTION {
        true
    } else if aaguid == AAGUID_DEVELOPMENT {
        false
    } else {
        return Err(AttestError::Policy);
    };
    if policy.production && !production {
        return Err(AttestError::Policy);
    }
    if credential_id != policy.key_id {
        return Err(AttestError::Key);
    }
    Ok(Attested {
        public_key: cert.public_key.to_vec(),
        production,
        receipt: receipt.to_vec(),
    })
}

#[cfg(test)]
mod tests;
