//! Token Status List (OP-150 m.3 (a), (s), L2-STL-1 to L2-STL-3): a projection's entry in one
//! list, the list token's payload, and the bit lookup. A list is an information channel, never
//! the safety mechanism (§9.12.4, PI-9): a verifier that cannot read a fresh list falls back to
//! the contract's horizon and Δ, fail-closed.

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::codec::{Canonical, Fields, ModelError, map, text, uint};

/// Content type of a list token as CWT (`COSE_Sign1`).
pub const CWT_CONTENT_TYPE: &str = "application/statuslist+cwt";
/// Media type of a list token as JWT.
pub const JWT_CONTENT_TYPE: &str = "application/statuslist+jwt";
/// Bits per entry; the only size Access uses (OP-150 m.3 (s)).
pub const BITS: u64 = 1;
/// Longest list `uri`.
pub const MAX_URI: usize = 2048;

const CWT_SUB: u64 = 2;
const CWT_EXP: u64 = 4;
const CWT_IAT: u64 = 6;
const CWT_STATUS_LIST: u64 = 65_533;
const CWT_TTL: u64 = 65_534;
const AS_OF: &str = "as_of";

/// A projection's entry: its index in the list at `uri` (CDDL `status-ref`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusRef {
    /// The index.
    pub idx: u64,
    /// The list's URI.
    pub uri: String,
}

impl Canonical for StatusRef {
    fn to_value(&self) -> Value {
        map([(
            "status_list",
            Some(map([
                ("idx", Some(Value::Unsigned(self.idx))),
                ("uri", Some(Value::text(&self.uri))),
            ])),
        )])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let mut l = Fields::of(f.req("status_list")?)?;
        let uri = text(l.req("uri")?)?;
        if uri.is_empty() || uri.len() > MAX_URI {
            return Err(ModelError::Range);
        }
        let r = Self {
            idx: uint(l.req("idx")?)?,
            uri: String::from(uri),
        };
        l.done()?;
        f.done()?;
        Ok(r)
    }
}

/// The payload of a list token (CDDL `status-list-cwt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListToken {
    /// The list's URI (`sub`).
    pub uri: String,
    /// `iat`, seconds: the `recorded_at` of the position the list reflects (T24).
    pub iat: u64,
    /// `exp`, seconds.
    pub exp: Option<u64>,
    /// `ttl`, seconds.
    pub ttl: Option<u64>,
    /// The ZLIB-compressed bytes (`lst`).
    pub lst: Vec<u8>,
    /// The aggregation URI.
    pub aggregation_uri: Option<String>,
    /// The canonical position the list reflects.
    pub as_of: u64,
}

/// Why a list or a lookup is refused (L2-STL-2, L2-STL-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StatusError {
    /// Not a list token payload.
    #[error("status-malformed")]
    Malformed,
    /// Not the list the reference names.
    #[error("status-uri")]
    Uri,
    /// The index lies past the end of the list.
    #[error("status-index")]
    Index,
}

impl StatusError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "status-malformed",
            Self::Uri => "status-uri",
            Self::Index => "status-index",
        }
    }
}

fn list_value(t: &ListToken) -> Value {
    map([
        ("bits", Some(Value::Unsigned(BITS))),
        ("lst", Some(Value::Bytes(t.lst.clone()))),
        (
            "aggregation_uri",
            t.aggregation_uri.as_ref().map(|u| Value::text(u)),
        ),
    ])
}

impl ListToken {
    /// The CWT claims map; integer keys are the CWT's, `as_of` is Access's.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = alloc::vec![
            (Value::Unsigned(CWT_SUB), Value::text(&self.uri)),
            (Value::Unsigned(CWT_IAT), Value::Unsigned(self.iat)),
            (Value::Unsigned(CWT_STATUS_LIST), list_value(self)),
            (Value::text(AS_OF), Value::Unsigned(self.as_of)),
        ];
        if let Some(exp) = self.exp {
            entries.push((Value::Unsigned(CWT_EXP), Value::Unsigned(exp)));
        }
        if let Some(ttl) = self.ttl {
            entries.push((Value::Unsigned(CWT_TTL), Value::Unsigned(ttl)));
        }
        Value::Map(entries)
    }

    /// Canonical bytes.
    ///
    /// # Errors
    /// The value is outside the structural limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>, dcbor::EncodeError> {
        dcbor::encode(&self.to_value(), Limits::CEILING)
    }

    /// Reads a list token payload (L2-STL-2).
    ///
    /// # Errors
    /// [`StatusError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatusError> {
        let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| StatusError::Malformed)?;
        Self::from_value(&v).ok_or(StatusError::Malformed)
    }

    fn from_value(v: &Value) -> Option<Self> {
        let Value::Map(entries) = v else {
            return None;
        };
        let (mut uri, mut iat, mut exp, mut ttl, mut list, mut as_of) =
            (None, None, None, None, None, None);
        for (k, val) in entries {
            match (k, val) {
                (Value::Unsigned(CWT_SUB), Value::Text(t))
                    if !t.is_empty() && t.len() <= MAX_URI =>
                {
                    uri = Some(t.clone());
                }
                (Value::Unsigned(CWT_IAT), Value::Unsigned(n)) => iat = Some(*n),
                (Value::Unsigned(CWT_EXP), Value::Unsigned(n)) => exp = Some(*n),
                (Value::Unsigned(CWT_TTL), Value::Unsigned(n)) => ttl = Some(*n),
                (Value::Unsigned(CWT_STATUS_LIST), l) => list = Some(l),
                (Value::Text(t), Value::Unsigned(n)) if t == AS_OF => as_of = Some(*n),
                _ => return None,
            }
        }
        let mut f = Fields::of(list?).ok()?;
        if uint(f.req("bits").ok()?).ok()? != BITS {
            return None;
        }
        let Value::Bytes(compressed) = f.req("lst").ok()? else {
            return None;
        };
        let aggregation_uri = match f.opt("aggregation_uri") {
            None => None,
            Some(Value::Text(t)) => Some(t.clone()),
            Some(_) => return None,
        };
        f.done().ok()?;
        Some(Self {
            uri: uri?,
            iat: iat?,
            exp,
            ttl,
            lst: compressed.clone(),
            aggregation_uri,
            as_of: as_of?,
        })
    }
}

/// Whether the entry at `idx` of the decompressed list is set (L2-STL-3): bit `idx mod 8` of
/// byte `idx div 8`, least significant first. A set bit is invalid.
///
/// # Errors
/// [`StatusError::Index`] past the end of the list.
pub fn is_set(decompressed: &[u8], idx: u64) -> Result<bool, StatusError> {
    let byte = usize::try_from(idx / 8).map_err(|_| StatusError::Index)?;
    let bit = u8::try_from(idx % 8).map_err(|_| StatusError::Index)?;
    let b = decompressed.get(byte).ok_or(StatusError::Index)?;
    Ok((b >> bit) & 1 == 1)
}

/// Looks up `reference` in a list token whose `lst` the caller has decompressed (L2-STL-3):
/// the token is for the referenced list and the bit is read. `true` is invalid.
///
/// # Errors
/// [`StatusError`].
pub fn lookup(
    token: &ListToken,
    decompressed: &[u8],
    reference: &StatusRef,
) -> Result<bool, StatusError> {
    if token.uri != reference.uri {
        return Err(StatusError::Uri);
    }
    is_set(decompressed, reference.idx)
}

#[cfg(test)]
mod tests;
