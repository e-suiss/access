//! Bounded CBOR reader for WebAuthn attestation objects and authenticator data (CR-10, §15.5.3).
//!
//! The input comes from authenticators and browsers, not from Access, so map key order and the
//! shortest-form rule are not enforced. Everything that changes meaning or costs memory is:
//! indefinite lengths, duplicate keys, tags, floats and simple values other than booleans are
//! rejected, and size, depth and item counts are capped before anything is allocated.

/// Ceiling for the whole input: the WebAuthn parser limit (Ek B Stage 1 carry-over, OP-125).
pub const MAX_INPUT: usize = 8 * 1024;

/// A decoded item borrowing from the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1; the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Item<'a>>),
    /// Major type 5, in input order.
    Map(Vec<(Item<'a>, Item<'a>)>),
    /// Simple values 20 and 21.
    Bool(bool),
}

impl<'a> Item<'a> {
    /// The signed value of an integer item, if it fits in `i64`.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Unsigned(u) => i64::try_from(u).ok(),
            Self::Negative(n) => i64::try_from(n).ok().and_then(|n| (-1_i64).checked_sub(n)),
            _ => None,
        }
    }

    /// The bytes of a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match *self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text of a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&'a str> {
        match *self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The entries of a map.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(Item<'a>, Item<'a>)]> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }

    /// The elements of an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Item<'a>]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Map lookup by integer key.
    #[must_use]
    pub fn get_int(&self, key: i64) -> Option<&Item<'a>> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_i64() == Some(key))
            .map(|(_, v)| v)
    }

    /// Map lookup by text key.
    #[must_use]
    pub fn get_text(&self, key: &str) -> Option<&Item<'a>> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }
}

/// Structural limits (CR-10 m.3). Ceilings are fixed; callers may only lower them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    input: usize,
    depth: usize,
    items: usize,
    total: usize,
}

impl Limits {
    /// Ceiling for container nesting.
    pub const MAX_DEPTH: usize = 16;
    /// Ceiling for entries in one array or map.
    pub const MAX_ITEMS: usize = 256;
    /// Ceiling for all data items in one input.
    pub const MAX_TOTAL: usize = 1024;

    /// The ceilings themselves.
    pub const CEILING: Self = Self {
        input: MAX_INPUT,
        depth: Self::MAX_DEPTH,
        items: Self::MAX_ITEMS,
        total: Self::MAX_TOTAL,
    };

    /// Tighter limits, or `None` if any value is above its ceiling.
    #[must_use]
    pub fn tightened(input: usize, depth: usize, items: usize, total: usize) -> Option<Self> {
        (input <= MAX_INPUT
            && depth <= Self::MAX_DEPTH
            && items <= Self::MAX_ITEMS
            && total <= Self::MAX_TOTAL)
            .then_some(Self {
                input,
                depth,
                items,
                total,
            })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::CEILING
    }
}

/// Why an input is rejected (CR-10 m.4: a protocol rejection, never a panic).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CborError {
    /// The input is larger than the limit, checked before decoding.
    #[error("input too large")]
    InputTooLarge,
    /// The input ended inside an item.
    #[error("truncated input")]
    Truncated,
    /// Bytes follow the single top-level item.
    #[error("trailing bytes")]
    TrailingBytes,
    /// Indefinite-length item or break code.
    #[error("indefinite length")]
    Indefinite,
    /// Reserved additional information value 28–30.
    #[error("reserved additional information")]
    Reserved,
    /// Floating-point value.
    #[error("float not allowed")]
    Float,
    /// Any tag.
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
    /// Nesting is deeper than the limit.
    #[error("nesting too deep")]
    Depth,
    /// A container has more entries than the limit.
    #[error("too many items")]
    Items,
    /// The input holds more data items than the limit.
    #[error("too many data items")]
    TotalItems,
}

impl CborError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputTooLarge => "cbor-input-too-large",
            Self::Truncated => "cbor-truncated",
            Self::TrailingBytes => "cbor-trailing-bytes",
            Self::Indefinite => "cbor-indefinite",
            Self::Reserved => "cbor-reserved",
            Self::Float => "cbor-float",
            Self::Tag => "cbor-tag",
            Self::Simple => "cbor-simple",
            Self::Utf8 => "cbor-utf8",
            Self::DuplicateKey => "cbor-duplicate-key",
            Self::Depth => "cbor-depth",
            Self::Items => "cbor-items",
            Self::TotalItems => "cbor-total-items",
        }
    }
}

/// Decodes exactly one item.
///
/// # Errors
/// [`CborError`].
pub fn decode(input: &[u8], limits: Limits) -> Result<Item<'_>, CborError> {
    let (item, used) = decode_prefix(input, limits)?;
    if used == input.len() {
        Ok(item)
    } else {
        Err(CborError::TrailingBytes)
    }
}

/// Decodes the first item of `input` and returns it with the number of bytes it took.
///
/// # Errors
/// [`CborError`].
pub fn decode_prefix(input: &[u8], limits: Limits) -> Result<(Item<'_>, usize), CborError> {
    if input.len() > limits.input {
        return Err(CborError::InputTooLarge);
    }
    let mut r = Reader {
        input,
        pos: 0,
        limits,
        seen: 0,
    };
    let item = r.item(0)?;
    Ok((item, r.pos))
}

enum Head {
    Value(u8, u64),
    Bool(bool),
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    limits: Limits,
    seen: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        let bytes = self.input.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn uint(&mut self, n: usize) -> Result<u64, CborError> {
        let mut buf = [0_u8; 8];
        for (d, s) in buf.iter_mut().rev().zip(self.take(n)?.iter().rev()) {
            *d = *s;
        }
        Ok(u64::from_be_bytes(buf))
    }

    fn head(&mut self) -> Result<Head, CborError> {
        let initial = *self.take(1)?.first().ok_or(CborError::Truncated)?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if major == 7 {
            return match info {
                20 => Ok(Head::Bool(false)),
                21 => Ok(Head::Bool(true)),
                25..=27 => Err(CborError::Float),
                28..=30 => Err(CborError::Reserved),
                31 => Err(CborError::Indefinite),
                _ => Err(CborError::Simple),
            };
        }
        let value = match info {
            0..=23 => u64::from(info),
            24 => self.uint(1)?,
            25 => self.uint(2)?,
            26 => self.uint(4)?,
            27 => self.uint(8)?,
            28..=30 => return Err(CborError::Reserved),
            _ => return Err(CborError::Indefinite),
        };
        Ok(Head::Value(major, value))
    }

    fn count(&mut self) -> Result<(), CborError> {
        self.seen = self.seen.checked_add(1).ok_or(CborError::TotalItems)?;
        if self.seen > self.limits.total {
            Err(CborError::TotalItems)
        } else {
            Ok(())
        }
    }

    fn enter(&self, depth: usize) -> Result<usize, CborError> {
        let next = depth.checked_add(1).ok_or(CborError::Depth)?;
        if next > self.limits.depth {
            Err(CborError::Depth)
        } else {
            Ok(next)
        }
    }

    fn entries(&self, arg: u64) -> Result<usize, CborError> {
        let n = usize::try_from(arg).map_err(|_| CborError::Items)?;
        if n > self.limits.items {
            Err(CborError::Items)
        } else {
            Ok(n)
        }
    }

    fn string(&mut self, arg: u64) -> Result<&'a [u8], CborError> {
        let n = usize::try_from(arg).map_err(|_| CborError::Truncated)?;
        self.take(n)
    }

    fn item(&mut self, depth: usize) -> Result<Item<'a>, CborError> {
        self.count()?;
        let (major, value) = match self.head()? {
            Head::Bool(b) => return Ok(Item::Bool(b)),
            Head::Value(major, value) => (major, value),
        };
        match major {
            0 => Ok(Item::Unsigned(value)),
            1 => Ok(Item::Negative(value)),
            2 => Ok(Item::Bytes(self.string(value)?)),
            3 => {
                let bytes = self.string(value)?;
                core::str::from_utf8(bytes)
                    .map(Item::Text)
                    .map_err(|_| CborError::Utf8)
            }
            4 => {
                let n = self.entries(value)?;
                let inner = self.enter(depth)?;
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.item(inner)?);
                }
                Ok(Item::Array(items))
            }
            5 => {
                let n = self.entries(value)?;
                let inner = self.enter(depth)?;
                let mut entries: Vec<(Item<'a>, Item<'a>)> = Vec::new();
                for _ in 0..n {
                    let key = self.item(inner)?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(CborError::DuplicateKey);
                    }
                    let val = self.item(inner)?;
                    entries.push((key, val));
                }
                Ok(Item::Map(entries))
            }
            6 => Err(CborError::Tag),
            _ => Err(CborError::Simple),
        }
    }
}

#[cfg(test)]
mod tests;
