//! Credential public keys in `COSE_Key` form (RFC 9052, RFC 9864) and assertion signatures
//! (§10.2.4 algorithms, CR-5, CR-9).

use access_crypto::webauthn::{
    p256_point_valid, rsa_key_valid, verify_ed25519, verify_es256, verify_rs256,
};
use access_parse::cbor::{Item, Limits, decode};

use super::Rejection;

const KTY: i64 = 1;
const ALG: i64 = 3;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;
const RSA_N: i64 = -1;
const RSA_E: i64 = -2;
const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const KTY_RSA: i64 = 3;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

/// The ML-DSA COSE algorithm identifiers (ML-DSA-44, -65, -87). WebAuthn L3 and CTAP 2.3 do
/// not define them for credentials; a credential that names one is refused (HL-19, CR-43).
pub const ML_DSA: [i64; 3] = [-48, -49, -50];

/// A credential algorithm Access accepts, in `pubKeyCredParams` order (§10.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoseAlgorithm {
    /// ESP256, fully specified (RFC 9864), −9.
    Esp256,
    /// ES256, −7: the mandatory verification algorithm.
    Es256,
    /// Ed25519, fully specified (RFC 9864), −19.
    Ed25519,
    /// `EdDSA`, −8, accepted only with `crv` = Ed25519.
    EdDsa,
    /// RS256, −257, for legacy authenticators and session login only.
    Rs256,
}

impl CoseAlgorithm {
    /// Preference order for `pubKeyCredParams`: ESP256/ES256 → Ed25519 → RS256.
    pub const PREFERENCE: [Self; 5] = [
        Self::Esp256,
        Self::Es256,
        Self::Ed25519,
        Self::EdDsa,
        Self::Rs256,
    ];

    /// The COSE algorithm identifier.
    #[must_use]
    pub const fn id(self) -> i64 {
        match self {
            Self::Esp256 => -9,
            Self::Es256 => -7,
            Self::Ed25519 => -19,
            Self::EdDsa => -8,
            Self::Rs256 => -257,
        }
    }

    /// From a COSE algorithm identifier.
    #[must_use]
    pub const fn from_id(id: i64) -> Option<Self> {
        match id {
            -9 => Some(Self::Esp256),
            -7 => Some(Self::Es256),
            -19 => Some(Self::Ed25519),
            -8 => Some(Self::EdDsa),
            -257 => Some(Self::Rs256),
            _ => None,
        }
    }
}

/// A parsed credential public key.
#[derive(Clone, PartialEq, Eq)]
pub enum CoseKey {
    /// P-256 for ES256 or ESP256: the uncompressed SEC1 point.
    P256 {
        /// −7 or −9.
        alg: CoseAlgorithm,
        /// `0x04 ‖ x ‖ y`.
        point: [u8; 65],
    },
    /// Ed25519 for alg −19, or −8 with `crv` = 6.
    Ed25519 {
        /// −19 or −8.
        alg: CoseAlgorithm,
        /// The public key.
        x: [u8; 32],
    },
    /// RSA for RS256.
    Rsa {
        /// Modulus.
        n: Vec<u8>,
        /// Public exponent.
        e: Vec<u8>,
    },
}

fn int(item: &Item<'_>, key: i64) -> Option<i64> {
    item.get_int(key).and_then(Item::as_i64)
}

fn bytes<'a>(item: &Item<'a>, key: i64) -> Option<&'a [u8]> {
    item.get_int(key).and_then(Item::as_bytes)
}

impl CoseKey {
    /// Parses a decoded `COSE_Key`. The key must name its algorithm, and the curve must fit it.
    ///
    /// # Errors
    /// [`Rejection::CoseKey`].
    pub fn from_item(item: &Item<'_>) -> Result<Self, Rejection> {
        let kty = int(item, KTY).ok_or(Rejection::CoseKey)?;
        let alg = int(item, ALG).ok_or(Rejection::CoseKey)?;
        // HL-19
        if ML_DSA.contains(&alg) {
            return Err(Rejection::Algorithm);
        }
        let alg = CoseAlgorithm::from_id(alg).ok_or(Rejection::CoseKey)?;
        match (kty, alg) {
            (KTY_EC2, CoseAlgorithm::Es256 | CoseAlgorithm::Esp256) => {
                if int(item, CRV) != Some(CRV_P256) {
                    return Err(Rejection::CoseKey);
                }
                let x = bytes(item, X)
                    .filter(|b| b.len() == 32)
                    .ok_or(Rejection::CoseKey)?;
                let y = bytes(item, Y)
                    .filter(|b| b.len() == 32)
                    .ok_or(Rejection::CoseKey)?;
                let mut point = [0_u8; 65];
                point[0] = 0x04;
                point
                    .get_mut(1..33)
                    .ok_or(Rejection::CoseKey)?
                    .copy_from_slice(x);
                point
                    .get_mut(33..)
                    .ok_or(Rejection::CoseKey)?
                    .copy_from_slice(y);
                if !p256_point_valid(&point) {
                    return Err(Rejection::CoseKey);
                }
                Ok(Self::P256 { alg, point })
            }
            (KTY_OKP, CoseAlgorithm::Ed25519 | CoseAlgorithm::EdDsa) => {
                if int(item, CRV) != Some(CRV_ED25519) {
                    return Err(Rejection::CoseKey);
                }
                let x = bytes(item, X)
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or(Rejection::CoseKey)?;
                Ok(Self::Ed25519 { alg, x })
            }
            (KTY_RSA, CoseAlgorithm::Rs256) => {
                let n = bytes(item, RSA_N).ok_or(Rejection::CoseKey)?;
                let e = bytes(item, RSA_E).ok_or(Rejection::CoseKey)?;
                if !rsa_key_valid(n, e) {
                    return Err(Rejection::CoseKey);
                }
                Ok(Self::Rsa {
                    n: n.to_vec(),
                    e: e.to_vec(),
                })
            }
            _ => Err(Rejection::CoseKey),
        }
    }

    /// Parses stored `COSE_Key` bytes.
    ///
    /// # Errors
    /// [`Rejection`].
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Rejection> {
        Self::from_item(&decode(raw, Limits::CEILING)?)
    }

    /// The key's algorithm.
    #[must_use]
    pub const fn alg(&self) -> CoseAlgorithm {
        match self {
            Self::P256 { alg, .. } | Self::Ed25519 { alg, .. } => *alg,
            Self::Rsa { .. } => CoseAlgorithm::Rs256,
        }
    }

    /// Verifies a WebAuthn signature over `authenticatorData ‖ SHA-256(clientDataJSON)`.
    ///
    /// # Errors
    /// [`Rejection::Signature`].
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Rejection> {
        let result = match self {
            Self::P256 { point, .. } => verify_es256(point, message, signature),
            Self::Ed25519 { x, .. } => verify_ed25519(x, message, signature),
            Self::Rsa { n, e } => verify_rs256(n, e, message, signature),
        };
        result.map_err(|_| Rejection::Signature)
    }
}
