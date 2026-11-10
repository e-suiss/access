//! CBOR as mdoc carries it (RFC 8949, ISO 18013-5 §8.1): preferred serialization with definite
//! lengths, any map key order, `null` allowed. Floats, `undefined`, other simple values,
//! indefinite lengths, non-shortest heads and duplicate map keys are refused. Because every head
//! is shortest, encoding a decoded `#6.24(bstr)` gives back the bytes a digest was taken over.

/// Deepest nesting.
pub const MAX_DEPTH: usize = 16;
/// Most entries in one array or map.
pub const MAX_ITEMS: usize = 1024;
/// Longest byte or text string (a portrait fits).
pub const MAX_STRING: usize = 512 * 1024;

/// A CBOR data item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cbor {
    /// Major type 0.
    Uint(u64),
    /// Major type 1; the value is `-1 - n`.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Cbor>),
    /// Major type 5, in the order received.
    Map(Vec<(Cbor, Cbor)>),
    /// Simple values 20 and 21.
    Bool(bool),
    /// Simple value 22.
    Null,
    /// Major type 6.
    Tag(u64, Box<Cbor>),
}

/// Why an input is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("cbor-malformed")]
pub struct CborError;

impl Cbor {
    /// A text item.
    #[must_use]
    pub fn text(s: &str) -> Self {
        Self::Text(String::from(s))
    }

    /// The map entry with text key `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.entry(|k| matches!(k, Self::Text(t) if t == key))
    }

    /// The map entry with integer key `key`.
    #[must_use]
    pub fn get_int(&self, key: i64) -> Option<&Self> {
        self.entry(|k| k.as_i64() == Some(key))
    }

    fn entry(&self, f: impl Fn(&Self) -> bool) -> Option<&Self> {
        match self {
            Self::Map(entries) => entries.iter().find(|(k, _)| f(k)).map(|(_, v)| v),
            _ => None,
        }
    }

    /// An integer item as `i64`.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Uint(n) => i64::try_from(*n).ok(),
            Self::Nint(n) => i64::try_from(*n).ok()?.checked_add(1)?.checked_neg(),
            _ => None,
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.input.get(self.at).ok_or(CborError)?;
        self.at = self.at.checked_add(1).ok_or(CborError)?;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
        let end = self.at.checked_add(n).ok_or(CborError)?;
        let s = self.input.get(self.at..end).ok_or(CborError)?;
        self.at = end;
        Ok(s)
    }

    fn head(&mut self) -> Result<(u8, u8, u64), CborError> {
        let b = self.byte()?;
        let (major, info) = (b >> 5, b & 0x1f);
        let arg = match info {
            0..=23 => u64::from(info),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(CborError);
                }
                v
            }
            25..=27 => {
                let (n, min) = match info {
                    25 => (2, 0x100),
                    26 => (4, 0x1_0000),
                    _ => (8, 0x1_0000_0000),
                };
                let mut v = 0_u64;
                for b in self.take(n)? {
                    v = (v << 8) | u64::from(*b);
                }
                if v < min {
                    return Err(CborError);
                }
                v
            }
            _ => return Err(CborError),
        };
        Ok((major, info, arg))
    }

    fn len(arg: u64, max: usize) -> Result<usize, CborError> {
        let n = usize::try_from(arg).map_err(|_| CborError)?;
        if n > max { Err(CborError) } else { Ok(n) }
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError);
        }
        let next = depth.saturating_add(1);
        let (major, info, arg) = self.head()?;
        Ok(match major {
            0 => Cbor::Uint(arg),
            1 => Cbor::Nint(arg),
            2 => Cbor::Bytes(self.take(Self::len(arg, MAX_STRING)?)?.to_vec()),
            3 => Cbor::Text(
                String::from_utf8(self.take(Self::len(arg, MAX_STRING)?)?.to_vec())
                    .map_err(|_| CborError)?,
            ),
            4 => {
                let n = Self::len(arg, MAX_ITEMS)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(next)?);
                }
                Cbor::Array(items)
            }
            5 => {
                let n = Self::len(arg, MAX_ITEMS)?;
                let mut entries: Vec<(Cbor, Cbor)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.item(next)?;
                    if entries.iter().any(|(e, _)| *e == k) {
                        return Err(CborError);
                    }
                    let v = self.item(next)?;
                    entries.push((k, v));
                }
                Cbor::Map(entries)
            }
            6 => Cbor::Tag(arg, Box::new(self.item(next)?)),
            _ => match info {
                20 => Cbor::Bool(false),
                21 => Cbor::Bool(true),
                22 => Cbor::Null,
                _ => return Err(CborError),
            },
        })
    }
}

/// Decodes exactly one item.
///
/// # Errors
/// [`CborError`].
pub fn decode(input: &[u8]) -> Result<Cbor, CborError> {
    let mut r = Reader { input, at: 0 };
    let item = r.item(0)?;
    if r.at == input.len() {
        Ok(item)
    } else {
        Err(CborError)
    }
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    let b = arg.to_be_bytes();
    match arg {
        0..=23 => out.push(m | b[7]),
        24..=0xff => out.extend_from_slice(&[m | 0x18, b[7]]),
        0x100..=0xffff => out.extend_from_slice(&[m | 0x19, b[6], b[7]]),
        0x1_0000..=0xffff_ffff => out.extend_from_slice(&[m | 0x1a, b[4], b[5], b[6], b[7]]),
        _ => {
            out.push(m | 0x1b);
            out.extend_from_slice(&b);
        }
    }
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn write(out: &mut Vec<u8>, v: &Cbor) {
    match v {
        Cbor::Uint(n) => head(out, 0, *n),
        Cbor::Nint(n) => head(out, 1, *n),
        Cbor::Bytes(b) => {
            head(out, 2, count(b.len()));
            out.extend_from_slice(b);
        }
        Cbor::Text(t) => {
            head(out, 3, count(t.len()));
            out.extend_from_slice(t.as_bytes());
        }
        Cbor::Array(items) => {
            head(out, 4, count(items.len()));
            for i in items {
                write(out, i);
            }
        }
        Cbor::Map(entries) => {
            head(out, 5, count(entries.len()));
            for (k, v) in entries {
                write(out, k);
                write(out, v);
            }
        }
        Cbor::Bool(false) => out.push(0xf4),
        Cbor::Bool(true) => out.push(0xf5),
        Cbor::Null => out.push(0xf6),
        Cbor::Tag(t, inner) => {
            head(out, 6, *t);
            write(out, inner);
        }
    }
}

/// Encodes with preferred serialization, map entries in their order.
#[must_use]
pub fn encode(v: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, v);
    out
}
