//! The approver's side of push verification (OP-156 m.3 (d), §10.2.3, `push-challenge.cddl`).
//! Any app that embeds this module is an approver: there is no Access store app and no approver
//! is privileged. The module is sans-I/O and never holds the key: the app keeps an app-bound P-256
//! key in its platform key store, signs the bytes this module gives it, and sends the bodies this
//! module builds.
//!
//! - **Register** after a sign-in in the last five minutes: [`registration_message`] is what the
//!   key signs to prove possession, [`registration_body`] is `POST /v1/approvers`.
//! - **Receive** a push from Relay: [`PushRequest::parse`] reads the `push_approval` body, and
//!   [`PushRequest::prompt`] is the text to show. The push never carries the number: the person
//!   reads it from the sign-in page and types it in.
//! - **Answer**: [`Answer::to_be_signed`] is the deterministic CBOR the key signs,
//!   [`answer_body`] is `POST /v1/push/answer`. "This wasn't me" is [`Decision::NotMe`].
//! - **Sign in inside the app itself**: [`same_device_message`] lets the key prove it started the
//!   flow, so its approval may come without the number; a sign-in started in a browser never
//!   gets this.
//!
//! Push is a second factor of AAL2 at best. It is not phishing resistant and meets no
//! Consequence Tier.
//!
//! ```
//! use access_sdk::approver::{Answer, Decision, to_raw_signature};
//!
//! let answer = Answer {
//!     challenge: [7; 32],
//!     number: Some(42),
//!     decision: Decision::Approve,
//!     device_key: [9; 32],
//!     pin_verified: None,
//! };
//! assert_eq!(answer.to_be_signed()[0], 0xa4);
//! assert!(to_raw_signature(&[0; 3]).is_none());
//! ```

pub mod inline;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;

/// Length of an uncompressed SEC1 P-256 public key.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Largest `push_approval` body read.
pub const MAX_PUSH: usize = 4 * 1024;

const REGISTRATION_CONTEXT: &str = "access/approver-registration/v1";
const SAME_DEVICE_CONTEXT: &str = "access/push-same-device/v1";

/// The P-256 group order.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Half the P-256 group order, rounded down.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// The RFC 7638 thumbprint of an uncompressed SEC1 P-256 public key: the approver's name in
/// Access and its Relay address. `None` when `public_key` is not one.
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

fn encode(v: &Value) -> Vec<u8> {
    dcbor::encode(v, Limits::CEILING).unwrap_or_default()
}

/// What the key signs when it is registered on the realm `issuer` (ES256).
#[must_use]
pub fn registration_message(issuer: &str, thumbprint: &[u8; 32]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::text(REGISTRATION_CONTEXT),
        Value::text(issuer),
        Value::Bytes(thumbprint.to_vec()),
    ]))
}

/// What the key signs to say it started the sign-in flow `handle` on `issuer` itself.
#[must_use]
pub fn same_device_message(issuer: &str, handle: &str) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::text(SAME_DEVICE_CONTEXT),
        Value::text(issuer),
        Value::text(handle),
    ]))
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ =
                    core::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The JSON body of `POST /v1/approvers`: the approver's name, its key and the raw `r ‖ s`
/// signature over [`registration_message`].
#[must_use]
pub fn registration_body(name: &str, public_key: &[u8], proof: &[u8; 64]) -> String {
    format!(
        r#"{{"name":{},"public_key":"{}","proof":"{}"}}"#,
        quote(name),
        b64url_encode(public_key),
        b64url_encode(proof)
    )
}

/// The JSON body of `POST /v1/push/challenge` for an in-app sign-in: the flow handle and the
/// key's signature over [`same_device_message`].
#[must_use]
pub fn same_device_body(handle: &str, thumbprint: &[u8; 32], signature: &[u8; 64]) -> String {
    format!(
        r#"{{"flow":{},"same_device":{{"device_key":"{}","signature":"{}"}}}}"#,
        quote(handle),
        b64url_encode(thumbprint),
        b64url_encode(signature)
    )
}

/// A push as Relay delivers it to the approver (`relay.message.push_approval.v1`).
#[derive(Clone, PartialEq, Eq)]
pub struct PushRequest {
    /// The challenge id to answer.
    pub challenge: [u8; 32],
    /// The application the person signs in to; attacker input, shown as text.
    pub application: String,
    /// What is being approved; attacker input, shown as text.
    pub action: String,
    /// The coarse location of the sign-in, when Access knew it.
    pub location: Option<String>,
    /// RFC 3339; after it the answer is refused.
    pub expires_at: String,
}

impl core::fmt::Debug for PushRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PushRequest")
            .field("application", &self.application)
            .finish_non_exhaustive()
    }
}

/// Why a push body is not a `push_approval`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not a push approval")]
pub struct NotAPush;

fn text(v: &Json, name: &str) -> Result<String, NotAPush> {
    v.get(name)
        .and_then(Json::as_str)
        .filter(|s| (1..=200).contains(&s.chars().count()))
        .map(String::from)
        .ok_or(NotAPush)
}

impl PushRequest {
    /// Reads the `data` object of a `push_approval` message.
    ///
    /// # Errors
    /// [`NotAPush`].
    pub fn parse(data: &[u8]) -> Result<Self, NotAPush> {
        let v = json::parse(data, MAX_PUSH).map_err(|_| NotAPush)?;
        let challenge = v
            .get("challenge")
            .and_then(Json::as_str)
            .and_then(|c| b64url_decode(c).ok())
            .and_then(|c| <[u8; 32]>::try_from(c).ok())
            .ok_or(NotAPush)?;
        let location = match v.get("location") {
            None => None,
            Some(Json::Str(s)) if (1..=200).contains(&s.chars().count()) => Some(s.clone()),
            Some(_) => return Err(NotAPush),
        };
        Ok(Self {
            challenge,
            application: text(&v, "application")?,
            action: text(&v, "action")?,
            location,
            expires_at: v
                .get("expires_at")
                .and_then(Json::as_str)
                .map(String::from)
                .ok_or(NotAPush)?,
        })
    }

    /// What the approver shows: the application and, when known, the coarse location; never the
    /// number, which the person reads from the sign-in page.
    #[must_use]
    pub fn prompt(&self) -> String {
        match &self.location {
            Some(place) => format!(
                "Sign-in request to {} from a browser, {place}. Enter the number shown.",
                self.application
            ),
            None => format!(
                "Sign-in request to {} from a browser. Enter the number shown.",
                self.application
            ),
        }
    }
}

/// What the person answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Approve; the number is required unless the app started the sign-in itself.
    Approve,
    /// Refuse.
    Deny,
    /// "This wasn't me": Access records a risk signal and tells the person.
    NotMe,
}

impl Decision {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::NotMe => "not_me",
        }
    }
}

/// A push answer (`push-challenge.cddl`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The challenge id from the push.
    pub challenge: [u8; 32],
    /// The number the person typed in, 10 to 99.
    pub number: Option<u8>,
    /// The decision.
    pub decision: Decision,
    /// The [`thumbprint`] of the signing key.
    pub device_key: [u8; 32],
    /// Whether the app checked its PIN on the device (the app-controlled factor, MD-11); the PIN
    /// itself never leaves the device.
    pub pin_verified: Option<bool>,
}

impl core::fmt::Debug for Answer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Answer")
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

impl Answer {
    /// The deterministic CBOR the key signs (ES256).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
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
        encode(&Value::Map(entries))
    }
}

/// The JSON body of `POST /v1/push/answer`: the signed bytes and the raw `r ‖ s` signature.
#[must_use]
pub fn answer_body(to_be_signed: &[u8], signature: &[u8; 64]) -> String {
    format!(
        r#"{{"answer":"{}","signature":"{}"}}"#,
        b64url_encode(to_be_signed),
        b64url_encode(signature)
    )
}

fn less(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}

fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut borrow = false;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b).rev() {
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(u8::from(borrow));
        *o = d;
        borrow = b1 || b2;
    }
    out
}

fn scalar(der: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&len, rest) = rest.split_first()?;
    let len = usize::from(len);
    if tag != 0x02 || len == 0 || len > 33 {
        return None;
    }
    let (int, rest) = rest.split_at_checked(len)?;
    let int = match int {
        [0, tail @ ..] if tail.first().is_some_and(|b| b & 0x80 != 0) => tail,
        [b, ..] if b & 0x80 != 0 => return None,
        [0, _, ..] => return None,
        i => i,
    };
    if int.len() > 32 {
        return None;
    }
    let mut out = [0_u8; 32];
    out.get_mut(32_usize.checked_sub(int.len())?..)?
        .copy_from_slice(int);
    Some((out, rest))
}

/// The raw `r ‖ s` form Access verifies, from a 64-byte raw or a DER (X9.62) ECDSA signature as
/// platform key stores return it, with S made low (CR-9). `None` when it is neither, or a scalar
/// is out of range.
#[must_use]
pub fn to_raw_signature(signature: &[u8]) -> Option<[u8; 64]> {
    let (r, s) = if signature.len() == 64 {
        let r = <[u8; 32]>::try_from(signature.get(..32)?).ok()?;
        let s = <[u8; 32]>::try_from(signature.get(32..)?).ok()?;
        (r, s)
    } else {
        let (&tag, rest) = signature.split_first()?;
        let (&len, rest) = rest.split_first()?;
        if tag != 0x30 || usize::from(len) != rest.len() {
            return None;
        }
        let (r, rest) = scalar(rest)?;
        let (s, rest) = scalar(rest)?;
        if !rest.is_empty() {
            return None;
        }
        (r, s)
    };
    let zero = [0_u8; 32];
    if r == zero || s == zero || !less(&r, &N) || !less(&s, &N) {
        return None;
    }
    let s = if less(&HALF_N, &s) { sub(&N, &s) } else { s };
    let mut out = [0_u8; 64];
    out.get_mut(..32)?.copy_from_slice(&r);
    out.get_mut(32..)?.copy_from_slice(&s);
    Some(out)
}

#[cfg(test)]
mod tests;
