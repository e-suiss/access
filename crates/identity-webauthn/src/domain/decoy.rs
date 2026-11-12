//! Passkey enumeration protection (TN-97, §12.4.1): an identifier without passkeys gets a
//! deterministic, plausible `allowCredentials` list, so the answer is the same whether the
//! account exists, has no passkey, or is locked.

use super::ids::{CredentialId, RealmId};
use super::options::CredentialDescriptor;

/// Plausible credential ID lengths, chosen per decoy.
const LENGTHS: [usize; 4] = [16, 32, 48, 64];
/// Most decoys an identifier gets; the count is drawn from 1 to this, like real accounts
/// (OP-159 m.11 (g)).
pub const MAX_DECOYS: u8 = 3;
/// Plausible transport sets, chosen per decoy.
const TRANSPORTS: [&[&str]; 3] = [&["internal", "hybrid"], &["usb", "nfc"], &["internal"]];

fn input(tag: u8, a: u8, b: u8, realm: RealmId, identifier: &str) -> Vec<u8> {
    let mut out = vec![tag, a, b];
    out.extend_from_slice(realm.as_bytes());
    out.extend_from_slice(identifier.as_bytes());
    out
}

fn pick<T: Copy>(table: &[T], byte: u8) -> Option<T> {
    let len = u8::try_from(table.len()).ok()?;
    table.get(usize::from(byte.checked_rem(len)?)).copied()
}

fn count(seed: &[u8; 32]) -> u8 {
    let wide = seed
        .first_chunk::<8>()
        .map_or(0, |b| u64::from_be_bytes(*b));
    let rem = wide.checked_rem(u64::from(MAX_DECOYS)).unwrap_or(0);
    u8::try_from(rem).map_or(1, |r| r.saturating_add(1))
}

/// One to [`MAX_DECOYS`] decoy descriptors for `identifier` (already normalized by the caller),
/// from a keyed derivation `derive` (CR-3 (a)). The same identifier always gets the same list,
/// and its length is keyed too, so it alone does not tell whether the account exists
/// (OP-159 m.11 (g)).
///
/// # Errors
/// Whatever `derive` returns.
pub fn decoy_descriptors<E>(
    realm: RealmId,
    identifier: &str,
    derive: impl Fn(&[u8]) -> Result<[u8; 32], E>,
) -> Result<Vec<CredentialDescriptor>, E> {
    let seed = derive(&input(b'n', 0, 0, realm, identifier))?;
    let count = count(&seed);
    let mut out = Vec::new();
    for i in 0..count {
        let shape = derive(&input(b's', i, 0, realm, identifier))?;
        let len = pick(&LENGTHS, shape[0]).unwrap_or(32);
        let transports = pick(&TRANSPORTS, shape[1]).unwrap_or(&["internal"]);
        let mut id = Vec::new();
        let mut block = 0_u8;
        while id.len() < len {
            id.extend_from_slice(&derive(&input(b'i', i, block, realm, identifier))?);
            block = block.saturating_add(1);
        }
        id.truncate(len);
        if let Some(id) = CredentialId::new(&id) {
            out.push(CredentialDescriptor {
                id,
                transports: transports.iter().map(|t| (*t).to_owned()).collect(),
            });
        }
    }
    Ok(out)
}
