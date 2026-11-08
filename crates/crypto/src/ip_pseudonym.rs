//! Keyed pseudonyms of client addresses (OP-151 m.1 (b), OP-47): what the risk engine keeps of
//! an IP instead of the address. The key lives in the PKCS#11 token and never leaves it; one
//! pseudonym per realm, so two realms cannot link one address.

#[cfg(any(test, feature = "testing"))]
use aws_lc_rs::hmac;
use suiss_crypto::pkcs11::{HsmError, HsmMac};

#[cfg(any(test, feature = "testing"))]
use crate::dit::DitGuard;
#[cfg(any(test, feature = "testing"))]
use crate::secret::Secret;

const CONTEXT: &[u8] = b"access/ip-pseudonym/v1\0";
const PREFIX_CONTEXT: &[u8] = b"access/ip-prefix-pseudonym/v1\0";

/// The address prefix a bootstrap rate context names: an IPv4 address (IPv4-mapped form) to
/// its /24, any other address to its /48; the rest is zeroed (§13.7.4, OP-152 m.5 (b)).
#[must_use]
pub fn prefix(address: &[u8; 16]) -> [u8; 16] {
    let mapped = address
        .iter()
        .enumerate()
        .take(12)
        .all(|(i, b)| *b == if i < 10 { 0 } else { 0xff });
    let keep = if mapped { 15 } else { 6 };
    let mut out = [0; 16];
    for (o, a) in out.iter_mut().zip(address).take(keep) {
        *o = *a;
    }
    out
}

/// The token label of the cell's address pseudonym key.
pub const LABEL: &str = "access/risk/ip-pseudonym";

enum Key {
    Token(HsmMac),
    #[cfg(any(test, feature = "testing"))]
    Memory(Secret<[u8; 32]>),
}

/// The cell's address pseudonym key.
pub struct IpPseudonymKey(Key);

impl IpPseudonymKey {
    /// The key inside the token.
    #[must_use]
    pub const fn token(mac: HsmMac) -> Self {
        Self(Key::Token(mac))
    }

    /// An in-process key with the same output as the token's, for tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn new(key: Secret<[u8; 32]>) -> Self {
        Self(Key::Memory(key))
    }

    /// `HMAC-SHA-256(K, "access/ip-pseudonym/v1" ‖ 0x00 ‖ tenant ‖ realm ‖ address)`, where the
    /// address is its 16-byte IPv6 form (IPv4 mapped).
    ///
    /// # Errors
    /// [`HsmError`] when the token refuses.
    pub fn pseudonym(
        &self,
        tenant: &[u8; 16],
        realm: &[u8; 16],
        address: &[u8; 16],
    ) -> Result<[u8; 32], HsmError> {
        self.mac(CONTEXT, tenant, realm, address)
    }

    /// `HMAC-SHA-256(K, "access/ip-prefix-pseudonym/v1" ‖ 0x00 ‖ tenant ‖ realm ‖ prefix)`, where
    /// the prefix is [`prefix`] of the address: the bootstrap rate context (OP-152 m.5 (b)).
    ///
    /// # Errors
    /// [`HsmError`] when the token refuses.
    pub fn prefix_pseudonym(
        &self,
        tenant: &[u8; 16],
        realm: &[u8; 16],
        address: &[u8; 16],
    ) -> Result<[u8; 32], HsmError> {
        self.mac(PREFIX_CONTEXT, tenant, realm, &prefix(address))
    }

    fn mac(
        &self,
        context: &[u8],
        tenant: &[u8; 16],
        realm: &[u8; 16],
        address: &[u8; 16],
    ) -> Result<[u8; 32], HsmError> {
        let mut message = context.to_vec();
        message.extend_from_slice(tenant);
        message.extend_from_slice(realm);
        message.extend_from_slice(address);
        match &self.0 {
            Key::Token(mac) => mac.mac(&message),
            #[cfg(any(test, feature = "testing"))]
            Key::Memory(key) => {
                // CR-39 m.6
                let _dit = DitGuard::new();
                let key = hmac::Key::new(hmac::HMAC_SHA256, key.expose());
                let mut out = [0; 32];
                out.copy_from_slice(hmac::sign(&key, &message).as_ref());
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.1 (b): stable per key and realm, unlinkable across realms and keys
    #[test]
    fn pseudonyms_are_per_realm() {
        let a = IpPseudonymKey::new(Secret::new([1; 32]));
        let b = IpPseudonymKey::new(Secret::new([2; 32]));
        let ip = [9; 16];
        let one = a.pseudonym(&[1; 16], &[2; 16], &ip).unwrap();
        assert_eq!(one, a.pseudonym(&[1; 16], &[2; 16], &ip).unwrap());
        assert_ne!(one, a.pseudonym(&[1; 16], &[3; 16], &ip).unwrap());
        assert_ne!(one, b.pseudonym(&[1; 16], &[2; 16], &ip).unwrap());
        assert_ne!(one, a.pseudonym(&[1; 16], &[2; 16], &[8; 16]).unwrap());
    }

    // OP-152 m.5 (b): one context per IPv4 /24 or IPv6 /48, apart from the address pseudonym
    #[test]
    fn prefix_pseudonyms_name_the_prefix() {
        let k = IpPseudonymKey::new(Secret::new([1; 32]));
        let v4 = |last: u8, third: u8| {
            let mut a = [0; 16];
            a[10] = 0xff;
            a[11] = 0xff;
            a[12..].copy_from_slice(&[192, 0, third, last]);
            a
        };
        let mut v6 = [0x20; 16];
        let p = |a: &[u8; 16]| k.prefix_pseudonym(&[1; 16], &[2; 16], a).unwrap();
        assert_eq!(p(&v4(1, 2)), p(&v4(200, 2)));
        assert_ne!(p(&v4(1, 2)), p(&v4(1, 3)));
        let one = p(&v6);
        v6[6] = 0;
        v6[15] = 1;
        assert_eq!(one, p(&v6));
        v6[5] = 0;
        assert_ne!(one, p(&v6));
        assert_ne!(
            p(&v4(1, 2)),
            k.pseudonym(&[1; 16], &[2; 16], &prefix(&v4(1, 2))).unwrap()
        );
    }
}
