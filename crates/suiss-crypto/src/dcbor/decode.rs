use alloc::string::String;
use alloc::vec::Vec;

use super::{COSE_SIGN1_TAG, DecodeError, Limits, Value};

/// Decodes exactly one canonical item and rejects everything outside the profile (CR-10).
///
/// # Errors
/// Any non-canonical or out-of-profile input.
pub fn decode(input: &[u8], limits: Limits) -> Result<Value, DecodeError> {
    let mut r = Reader {
        input,
        pos: 0,
        limits,
    };
    let value = r.item(0)?;
    r.finish()?;
    Ok(value)
}

/// Decodes one item wrapped in the given tag (OP-106 m.3: only tag 18).
///
/// # Errors
/// A different or missing tag, or any [`decode`] error inside.
pub fn decode_tagged(input: &[u8], tag: u64, limits: Limits) -> Result<Value, DecodeError> {
    if tag != COSE_SIGN1_TAG {
        return Err(DecodeError::Tag);
    }
    let mut r = Reader {
        input,
        pos: 0,
        limits,
    };
    let (major, arg) = r.head()?;
    if major != 6 || arg != Arg::Value(tag) {
        return Err(DecodeError::Tag);
    }
    let value = r.item(0)?;
    r.finish()?;
    Ok(value)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arg {
    Value(u64),
    Simple(u8),
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl<'a> Reader<'a> {
    fn finish(&self) -> Result<(), DecodeError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let bytes = self
            .input
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        self.take(1)?.first().copied().ok_or(DecodeError::Truncated)
    }

    fn uint(&mut self, n: usize) -> Result<u64, DecodeError> {
        let mut buf = [0_u8; 8];
        for (d, s) in buf.iter_mut().rev().zip(self.take(n)?.iter().rev()) {
            *d = *s;
        }
        Ok(u64::from_be_bytes(buf))
    }

    fn head(&mut self) -> Result<(u8, Arg), DecodeError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if major == 7 {
            return match info {
                20..=23 => Ok((7, Arg::Simple(info))),
                25..=27 => Err(DecodeError::Float),
                31 => Err(DecodeError::Indefinite),
                _ => Err(DecodeError::Simple),
            };
        }
        let value = match info {
            0..=23 => u64::from(info),
            24 => self.min_width(1, 24)?,
            25 => self.min_width(2, 0x100)?,
            26 => self.min_width(4, 0x1_0000)?,
            27 => self.min_width(8, 0x1_0000_0000)?,
            28..=30 => return Err(DecodeError::Reserved),
            _ => return Err(DecodeError::Indefinite),
        };
        Ok((major, Arg::Value(value)))
    }

    fn min_width(&mut self, n: usize, min: u64) -> Result<u64, DecodeError> {
        let v = self.uint(n)?;
        if v < min {
            Err(DecodeError::NonShortest)
        } else {
            Ok(v)
        }
    }

    fn len(arg: u64, cap: usize, err: DecodeError) -> Result<usize, DecodeError> {
        let n = usize::try_from(arg).map_err(|_| err)?;
        if n > cap { Err(err) } else { Ok(n) }
    }

    fn item(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let (major, arg) = self.head()?;
        let value = match arg {
            Arg::Simple(20) => return Ok(Value::Bool(false)),
            Arg::Simple(21) => return Ok(Value::Bool(true)),
            Arg::Simple(_) => return Err(DecodeError::Simple),
            Arg::Value(v) => v,
        };
        match major {
            0 => Ok(Value::Unsigned(value)),
            1 => Ok(Value::Negative(value)),
            2 => {
                let n = Self::len(value, self.limits.string, DecodeError::StringLength)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = Self::len(value, self.limits.string, DecodeError::StringLength)?;
                let s = core::str::from_utf8(self.take(n)?).map_err(|_| DecodeError::Utf8)?;
                Ok(Value::Text(String::from(s)))
            }
            4 => {
                let n = Self::len(value, self.limits.items, DecodeError::Items)?;
                let inner = self.enter(depth)?;
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.item(inner)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = Self::len(value, self.limits.items, DecodeError::Items)?;
                let inner = self.enter(depth)?;
                let mut entries = Vec::new();
                let mut previous: Option<&'a [u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let key = self.item(inner)?;
                    let whole: &'a [u8] = self.input;
                    let key_bytes = whole.get(start..self.pos).ok_or(DecodeError::Truncated)?;
                    if let Some(prev) = previous {
                        match prev.cmp(key_bytes) {
                            core::cmp::Ordering::Less => {}
                            core::cmp::Ordering::Equal => return Err(DecodeError::DuplicateKey),
                            core::cmp::Ordering::Greater => return Err(DecodeError::KeyOrder),
                        }
                    }
                    previous = Some(key_bytes);
                    let val = self.item(inner)?;
                    entries.push((key, val));
                }
                Ok(Value::Map(entries))
            }
            6 => Err(DecodeError::Tag),
            _ => Err(DecodeError::Simple),
        }
    }

    fn enter(&self, depth: usize) -> Result<usize, DecodeError> {
        let next = depth.checked_add(1).ok_or(DecodeError::Depth)?;
        if next > self.limits.depth {
            Err(DecodeError::Depth)
        } else {
            Ok(next)
        }
    }
}
