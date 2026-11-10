//! The approver's wire forms (OP-156 m.3 (d), §10.1.3, `push-challenge.cddl`): the RFC 7638
//! thumbprint that names an approver key, what the key signs to prove possession at registration
//! and to start an in-app sign-in, and the push answer it signs. Every signature is ES256 with a
//! raw `r ‖ s` and low S (CR-9) over deterministic CBOR (RFC 8949 §4.2.1).

use access_kernel::json::b64url_encode;
use suiss_crypto::aws::AwsLcBackend;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;

/// Length of an uncompressed SEC1 P-256 public key.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Length of a push challenge id.
pub const CHALLENGE_LEN: usize = 32;

/// The smallest number the sign-in page shows.
pub const NUMBER_MIN: u8 = 10;

/// The largest number the sign-in page shows.
pub const NUMBER_MAX: u8 = 99;

/// Longest push answer accepted, in bytes.
pub const MAX_ANSWER: usize = 256;

const REGISTRATION_CONTEXT: &str = "access/approver-registration/v1";
const SAME_DEVICE_CONTEXT: &str = "access/push-same-device/v1";

/// The RFC 7638 thumbprint of an uncompressed SEC1 P-256 key; `None` when `public_key` is not
/// one.
#[must_use]
pub fn thumbprint(public_key: &[u8]) -> Option<[u8; 32]> {
    if public_key.len() != PUBLIC_KEY_LEN || public_key.first() != Some(&4) {
        return None;
    }
    let x = public_key.get(1..33)?;
    let y = public_key.get(33..65)?;
    let jwk = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        b64url_encode(x),
        b64url_encode(y)
    );
    Some(sha256(jwk.as_bytes()))
}

/// What an approver key signs when it is registered on `issuer`: proof that the person holds it.
#[must_use]
pub fn registration_message(issuer: &str, thumbprint: &[u8; 32]) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(vec![
            Value::text(REGISTRATION_CONTEXT),
            Value::text(issuer),
            Value::Bytes(thumbprint.to_vec()),
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// What an approver key signs to say it started the sign-in flow `handle` on `issuer` itself:
/// the only case where its answer may come without the number (OP-156 m.3 (d)).
#[must_use]
pub fn same_device_message(issuer: &str, handle: &str) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(vec![
            Value::text(SAME_DEVICE_CONTEXT),
            Value::text(issuer),
            Value::text(handle),
        ]),
        Limits::CEILING,
    )
    .unwrap_or_default()
}

/// Whether `signature` is `public_key`'s ES256 signature over `message`, low S.
#[must_use]
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    suiss_crypto::sig::p256(&AwsLcBackend, public_key, message, signature, true).is_ok()
}

/// What the person answered on the approver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Approve the sign-in.
    Approve,
    /// Refuse it.
    Deny,
    /// "This wasn't me".
    NotMe,
}

impl Decision {
    /// The wire and stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::NotMe => "not_me",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Approve, Self::Deny, Self::NotMe]
            .into_iter()
            .find(|d| d.name() == s)
    }
}

/// A decoded push answer (`push-challenge.cddl`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The challenge id.
    pub challenge: [u8; CHALLENGE_LEN],
    /// The number typed in.
    pub number: Option<u8>,
    /// The decision.
    pub decision: Decision,
    /// The thumbprint of the signing key.
    pub device_key: [u8; 32],
    /// The app-controlled factor's declaration (MD-11).
    pub pin_verified: Option<bool>,
}

impl core::fmt::Debug for Answer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Answer")
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

/// Why an answer's bytes are not a push answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed push answer")]
pub struct Malformed;

fn bytes32(v: &Value) -> Result<[u8; 32], Malformed> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| Malformed),
        _ => Err(Malformed),
    }
}

impl Answer {
    /// Decodes the deterministic CBOR an approver signed. Unknown members, a number outside
    /// 10–99 or non-canonical bytes are [`Malformed`].
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() > MAX_ANSWER {
            return Err(Malformed);
        }
        let limits = Limits::tightened(2, 8, 64).ok_or(Malformed)?;
        let Value::Map(entries) = dcbor::decode(bytes, limits).map_err(|_| Malformed)? else {
            return Err(Malformed);
        };
        let mut challenge = None;
        let mut number = None;
        let mut decision = None;
        let mut device_key = None;
        let mut pin_verified = None;
        for (k, v) in &entries {
            let Value::Text(k) = k else {
                return Err(Malformed);
            };
            match (k.as_str(), v) {
                ("challenge", v) => challenge = Some(bytes32(v)?),
                ("number", Value::Unsigned(n)) => {
                    let n = u8::try_from(*n).map_err(|_| Malformed)?;
                    if !(NUMBER_MIN..=NUMBER_MAX).contains(&n) {
                        return Err(Malformed);
                    }
                    number = Some(n);
                }
                ("decision", Value::Text(d)) => {
                    decision = Some(Decision::parse(d).ok_or(Malformed)?);
                }
                ("device_key", v) => device_key = Some(bytes32(v)?),
                ("pin_verified", Value::Bool(b)) => pin_verified = Some(*b),
                _ => return Err(Malformed),
            }
        }
        Ok(Self {
            challenge: challenge.ok_or(Malformed)?,
            number,
            decision: decision.ok_or(Malformed)?,
            device_key: device_key.ok_or(Malformed)?,
            pin_verified,
        })
    }

    /// The deterministic CBOR of the answer, the bytes an approver signs.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::text("challenge"),
                Value::Bytes(self.challenge.to_vec()),
            ),
            (Value::text("decision"), Value::text(self.decision.name())),
            (
                Value::text("device_key"),
                Value::Bytes(self.device_key.to_vec()),
            ),
        ];
        if let Some(n) = self.number {
            entries.push((Value::text("number"), Value::Unsigned(u64::from(n))));
        }
        if let Some(p) = self.pin_verified {
            entries.push((Value::text("pin_verified"), Value::Bool(p)));
        }
        dcbor::encode(&Value::Map(entries), Limits::CEILING).unwrap_or_default()
    }
}

/// The number the sign-in page shows, from one byte of fresh randomness; `None` asks for another
/// byte so every number is equally likely.
#[must_use]
pub const fn number_of(byte: u8) -> Option<u8> {
    if byte >= 180 {
        return None;
    }
    match byte.checked_rem(90) {
        Some(r) => NUMBER_MIN.checked_add(r),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "test code"
    )]

    use super::*;

    // OP-156 m.3 (d)
    #[test]
    fn numbers_are_two_digits_and_uniform() {
        let mut seen = [0_u32; 100];
        for b in 0..=u8::MAX {
            if let Some(n) = number_of(b) {
                assert!((10..=99).contains(&n));
                seen[usize::from(n)] += 1;
            }
        }
        assert!(seen[10..].iter().all(|c| *c == 2));
    }

    // OP-156 m.3 (d)
    #[test]
    fn an_answer_round_trips_and_extra_members_are_refused() {
        let a = Answer {
            challenge: [7; 32],
            number: Some(42),
            decision: Decision::Approve,
            device_key: [9; 32],
            pin_verified: None,
        };
        let bytes = a.encode();
        assert_eq!(Answer::decode(&bytes), Ok(a));
        let extra = dcbor::encode(
            &Value::Map(vec![
                (Value::text("x"), Value::Unsigned(1)),
                (Value::text("challenge"), Value::Bytes(vec![7; 32])),
                (Value::text("decision"), Value::text("approve")),
                (Value::text("device_key"), Value::Bytes(vec![9; 32])),
            ]),
            Limits::CEILING,
        )
        .unwrap_or_default();
        assert_eq!(Answer::decode(&extra), Err(Malformed));
        let low = Answer {
            number: Some(9),
            ..a
        };
        assert_eq!(Answer::decode(&low.encode()), Err(Malformed));
    }

    // RFC 7638 §3
    #[test]
    fn a_thumbprint_needs_an_uncompressed_point() {
        let mut key = [1_u8; 65];
        key[0] = 4;
        assert!(thumbprint(&key).is_some());
        key[0] = 2;
        assert!(thumbprint(&key).is_none());
        assert!(thumbprint(&[4; 33]).is_none());
    }
}
