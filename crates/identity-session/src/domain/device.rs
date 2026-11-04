//! Device Instances from a user session (OP-149 m.6, m.16 (a)): the session a registration or
//! termination needs, the `COSE_Key` a device presents and its RFC 7638 `kid` (CR-24). The
//! proof of possession is the device's own `instance_create` Exercise, whose nonce is a
//! single-use server challenge; the authority plane verifies its signature.

use access_parse::cbor::{Item, Limits, decode};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Value};

use super::assurance::Aal;

/// How recent the step-up must be (OP-149 m.6, PD).
pub const STEP_UP_WINDOW_MS: u64 = 5 * 60 * 1000;

/// The assurance a device registration or termination needs (OP-149 m.6).
pub const MIN_AAL: Aal = Aal::Aal2;

/// How long a challenge may be answered (PD).
pub const CHALLENGE_TTL_MS: u64 = 5 * 60 * 1000;

/// Largest `COSE_Key` accepted, in bytes.
pub const MAX_KEY: usize = 256;

const KTY: i64 = 1;
const ALG: i64 = 3;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;
const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

/// Why a session may not register or terminate a device Instance now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assurance {
    /// AAL2 or more, authenticated or stepped up within [`STEP_UP_WINDOW_MS`].
    Fresh,
    /// The session's assurance is below [`MIN_AAL`].
    TooWeak,
    /// The last authentication is older than [`STEP_UP_WINDOW_MS`].
    Stale,
}

/// OP-149 m.6: AAL2 and an authentication within the window. A step-up restamps the session's
/// authentication time, so a fresh sign-in at AAL2 counts as well.
#[must_use]
pub const fn assurance(aal: Aal, auth_time_ms: u64, now_ms: u64) -> Assurance {
    if (aal as u8) < (MIN_AAL as u8) {
        return Assurance::TooWeak;
    }
    if now_ms.saturating_sub(auth_time_ms) > STEP_UP_WINDOW_MS {
        return Assurance::Stale;
    }
    Assurance::Fresh
}

/// Why a presented key or proof is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyRejection {
    /// Not a `COSE_Key` for Ed25519 or P-256, or not a valid point (OP-149 m.14 (a)).
    #[error("key")]
    Key,
    /// The key's own Exercise does not verify: its AIS is not by that key over the request.
    #[error("proof of possession")]
    Pop,
}

impl KeyRejection {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Key => "invalid-instance-key",
            Self::Pop => "invalid-proof-of-possession",
        }
    }
}

fn int(item: &Item<'_>, key: i64) -> Option<i64> {
    item.get_int(key).and_then(Item::as_i64)
}

fn bytes<'a>(item: &Item<'a>, key: i64) -> Option<&'a [u8]> {
    item.get_int(key).and_then(Item::as_bytes)
}

/// An Instance key from its `COSE_Key` (RFC 9052 §7): OKP Ed25519 (`alg` −19 or −8, or none)
/// or EC2 P-256 (`alg` −9 or −7, or none) (OP-149 m.6, m.14 (a), (b)).
///
/// # Errors
/// [`KeyRejection::Key`].
pub fn instance_key(cose_key: &[u8]) -> Result<PublicKey, KeyRejection> {
    if cose_key.len() > MAX_KEY {
        return Err(KeyRejection::Key);
    }
    let item = decode(cose_key, Limits::CEILING).map_err(|_| KeyRejection::Key)?;
    if item.as_map().is_none() {
        return Err(KeyRejection::Key);
    }
    let alg = match item.get_int(ALG) {
        None => None,
        Some(a) => Some(a.as_i64().ok_or(KeyRejection::Key)?),
    };
    let key = match (int(&item, KTY), int(&item, CRV)) {
        (Some(KTY_OKP), Some(CRV_ED25519)) if matches!(alg, None | Some(-19 | -8)) => {
            let x = bytes(&item, X)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or(KeyRejection::Key)?;
            PublicKey::Ed25519(x)
        }
        (Some(KTY_EC2), Some(CRV_P256)) if matches!(alg, None | Some(-9 | -7)) => {
            let x = bytes(&item, X).filter(|b| b.len() == 32);
            let y = bytes(&item, Y).filter(|b| b.len() == 32);
            let (Some(x), Some(y)) = (x, y) else {
                return Err(KeyRejection::Key);
            };
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            PublicKey::P256(sec1)
        }
        _ => return Err(KeyRejection::Key),
    };
    key.check().map_err(|_| KeyRejection::Key)?;
    Ok(key)
}

/// The key's `COSE_Key` in deterministic CBOR, without `alg`: how Access hands a key back.
#[must_use]
pub fn cose_key(key: &PublicKey) -> Vec<u8> {
    let v = match key {
        PublicKey::Ed25519(x) => Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(1)),
            (Value::int(-1), Value::Unsigned(6)),
            (Value::int(-2), Value::Bytes(x.to_vec())),
        ]),
        PublicKey::P256(sec1) => {
            let (x, y) = sec1
                .get(1..)
                .and_then(|xy| xy.split_at_checked(32))
                .unwrap_or_default();
            Value::Map(vec![
                (Value::Unsigned(1), Value::Unsigned(2)),
                (Value::int(-1), Value::Unsigned(1)),
                (Value::int(-2), Value::Bytes(x.to_vec())),
                (Value::int(-3), Value::Bytes(y.to_vec())),
            ])
        }
        PublicKey::MlDsa(..) => Value::Map(Vec::new()),
    };
    dcbor::encode(&v, dcbor::Limits::CEILING).unwrap_or_default()
}

/// The key's `kid`: its RFC 7638 JWK thumbprint (CR-24).
#[must_use]
pub fn kid(key: &PublicKey) -> [u8; 32] {
    access_kernel::verify::key_scope::thumbprint(key)
}

#[cfg(test)]
mod tests;
