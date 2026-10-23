//! Deterministic CBOR (RFC 8949 §4.2.1) with the Access profile (OP-106 m.1–m.6).

mod decode;
mod encode;

use alloc::string::String;
use alloc::vec::Vec;

pub use decode::{decode, decode_tagged};
pub use encode::encode;

/// A CBOR data item allowed by the profile: no floats, no tags inside, no null or undefined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1; the encoded value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5, entries in canonical key order after decoding.
    Map(Vec<(Value, Value)>),
    /// Simple values 20 and 21.
    Bool(bool),
}

impl Value {
    /// A text value.
    #[must_use]
    pub fn text(s: &str) -> Self {
        Self::Text(String::from(s))
    }

    /// A signed integer value.
    #[must_use]
    pub fn int(n: i64) -> Self {
        match u64::try_from(n) {
            Ok(u) => Self::Unsigned(u),
            Err(_) => Self::Negative(n.unsigned_abs().wrapping_sub(1)),
        }
    }

    /// The signed value of an integer item, if it fits in `i64`.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Unsigned(u) => i64::try_from(u).ok(),
            Self::Negative(n) => i64::try_from(n).ok().and_then(|n| (-1_i64).checked_sub(n)),
            _ => None,
        }
    }

    /// Map lookup by text key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Self::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

/// The only tag allowed, and only on the outside of a COSE structure (OP-106 m.3).
pub const COSE_SIGN1_TAG: u64 = 18;

/// Structural limits (§14.6). Ceilings are fixed; callers may only lower them (OP-106 m.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    depth: usize,
    items: usize,
    string: usize,
}

impl Limits {
    /// Ceiling for container nesting.
    pub const MAX_DEPTH: usize = 16;
    /// Ceiling for entries in one array or map.
    pub const MAX_ITEMS: usize = 256;
    /// Ceiling for one byte or text string.
    pub const MAX_STRING: usize = 64 * 1024;

    /// The ceilings themselves.
    pub const CEILING: Self = Self {
        depth: Self::MAX_DEPTH,
        items: Self::MAX_ITEMS,
        string: Self::MAX_STRING,
    };

    /// Tighter limits, or `None` if any value is above its ceiling.
    #[must_use]
    pub fn tightened(depth: usize, items: usize, string: usize) -> Option<Self> {
        (depth <= Self::MAX_DEPTH && items <= Self::MAX_ITEMS && string <= Self::MAX_STRING)
            .then_some(Self {
                depth,
                items,
                string,
            })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::CEILING
    }
}

/// Why an input is not accepted (CR-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input ended inside an item.
    #[error("truncated input")]
    Truncated,
    /// Bytes follow the single top-level item.
    #[error("trailing bytes")]
    TrailingBytes,
    /// An integer or length was not encoded in its shortest form.
    #[error("non-shortest integer encoding")]
    NonShortest,
    /// Indefinite-length item.
    #[error("indefinite length")]
    Indefinite,
    /// Reserved additional information value 28–30.
    #[error("reserved additional information")]
    Reserved,
    /// Floating-point value.
    #[error("float not allowed")]
    Float,
    /// Tag not allowed here.
    #[error("tag not allowed")]
    Tag,
    /// Null, undefined or another simple value.
    #[error("simple value not allowed")]
    Simple,
    /// Text string is not valid UTF-8.
    #[error("invalid UTF-8")]
    Utf8,
    /// The same map key appears twice.
    #[error("duplicate map key")]
    DuplicateKey,
    /// Map keys are not in canonical order.
    #[error("map keys out of order")]
    KeyOrder,
    /// Nesting is deeper than the limit.
    #[error("nesting too deep")]
    Depth,
    /// A container has more entries than the limit.
    #[error("too many items")]
    Items,
    /// A string is longer than the limit.
    #[error("string too long")]
    StringLength,
}

/// Why a value cannot be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// Two map entries have the same key.
    #[error("duplicate map key")]
    DuplicateKey,
    /// The value is outside the structural limits.
    #[error("value outside limits")]
    Limits,
}

#[cfg(test)]
mod tests;
