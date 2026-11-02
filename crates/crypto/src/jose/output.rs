//! JSON output for JOSE payloads: the Kernel's strict I-JSON value written compactly, and
//! canonical dCBOR values mapped to it (L0-ENC-20, L0-ENC-21, L1-ADP-6).

use std::fmt::Write as _;

use access_kernel::digest::Digest;
use access_kernel::json::{Json, b64url_encode};
use access_kernel::verify::projection::digest_text;
use suiss_crypto::dcbor::Value;

/// Largest integer magnitude written, the I-JSON range `2^53 − 1` (RFC 7493 §2.2).
pub const MAX_INT: i64 = (1 << 53) - 1;

/// Why a value has no JSON form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JsonOutError {
    /// An integer outside the I-JSON range.
    #[error("integer out of range")]
    Range,
    /// A map key that is not text, or a tag.
    #[error("shape")]
    Shape,
}

/// `value` as compact JSON text.
#[must_use]
pub fn to_string(value: &Json) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Str(s) => string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Json::Object(members) => {
            out.push('{');
            for (n, (k, v)) in members.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                string(k, out);
                out.push(':');
                write(v, out);
            }
            out.push('}');
        }
    }
}

fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON string.
#[must_use]
pub fn text(s: &str) -> Json {
    Json::Str(String::from(s))
}

/// A JSON integer within the I-JSON range.
///
/// # Errors
/// [`JsonOutError::Range`].
pub fn int(n: u64) -> Result<Json, JsonOutError> {
    i64::try_from(n)
        .ok()
        .filter(|n| *n <= MAX_INT)
        .map(Json::Int)
        .ok_or(JsonOutError::Range)
}

/// A digest in its tagged text form (L0-ENC-21).
#[must_use]
pub fn digest(d: &Digest) -> Json {
    Json::Str(digest_text(d))
}

/// A canonical dCBOR value as JSON: text and booleans as such, integers in the I-JSON range,
/// a digest `[-16, h]` in its text form (L0-ENC-21), other binaries base64url (L1-ADP-6), maps
/// with text keys as objects in canonical order.
///
/// # Errors
/// [`JsonOutError`].
pub fn from_cbor(v: &Value) -> Result<Json, JsonOutError> {
    Ok(match v {
        Value::Unsigned(n) => int(*n)?,
        Value::Negative(n) => Json::Int(
            i64::try_from(*n)
                .ok()
                .filter(|n| *n < MAX_INT)
                .and_then(|n| n.checked_add(1))
                .and_then(i64::checked_neg)
                .ok_or(JsonOutError::Range)?,
        ),
        Value::Bytes(b) => Json::Str(b64url_encode(b)),
        Value::Text(t) => Json::Str(t.clone()),
        Value::Bool(b) => Json::Bool(*b),
        Value::Array(items) => match items.as_slice() {
            [Value::Negative(15), Value::Bytes(h)] => {
                let h = <[u8; 32]>::try_from(h.as_slice()).map_err(|_| JsonOutError::Shape)?;
                digest(&Digest(h))
            }
            _ => Json::Array(items.iter().map(from_cbor).collect::<Result<_, _>>()?),
        },
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| match k {
                    Value::Text(k) => Ok((k.clone(), from_cbor(v)?)),
                    _ => Err(JsonOutError::Shape),
                })
                .collect::<Result<_, _>>()?,
        ),
        Value::Tag(..) => return Err(JsonOutError::Shape),
    })
}
