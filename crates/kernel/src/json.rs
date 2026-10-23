//! Strict I-JSON for JOSE headers and SD-JWT payloads only (OP-110 m.2), and strict base64url.

use alloc::string::String;
use alloc::vec::Vec;

/// A JSON value. Objects keep member order; numbers are integers only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// String.
    Str(String),
    /// Array.
    Array(Vec<Json>),
    /// Object without repeated member names.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Object member by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Self::Object(m) => m.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The integer, if this is one.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// Maximum nesting (§14.6).
pub const MAX_DEPTH: usize = 32;

/// Why JSON input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// Input larger than the limit, checked before parsing.
    #[error("input too large")]
    Size,
    /// Nesting deeper than 32.
    #[error("nesting too deep")]
    Depth,
    /// Not UTF-8.
    #[error("invalid UTF-8")]
    Utf8,
    /// Syntax error, trailing data or a lone surrogate.
    #[error("syntax error")]
    Syntax,
    /// Fractions, exponents or integers outside `i64`.
    #[error("number not allowed")]
    Number,
    /// A member name appears twice.
    #[error("duplicate member")]
    Duplicate,
}

/// Parses one JSON value from `input`, which must not exceed `max_len` bytes.
///
/// # Errors
/// [`JsonError`].
pub fn parse(input: &[u8], max_len: usize) -> Result<Json, JsonError> {
    if input.len() > max_len {
        return Err(JsonError::Size);
    }
    let text = core::str::from_utf8(input).map_err(|_| JsonError::Utf8)?;
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.pos == p.s.len() {
        Ok(v)
    } else {
        Err(JsonError::Syntax)
    }
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn bump(&mut self) -> Result<u8, JsonError> {
        let b = self.peek().ok_or(JsonError::Syntax)?;
        self.pos = self.pos.checked_add(1).ok_or(JsonError::Syntax)?;
        Ok(b)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos = self.pos.checked_add(1).unwrap_or(self.s.len());
        }
    }

    fn lit(&mut self, word: &[u8], v: Json) -> Result<Json, JsonError> {
        let end = self.pos.checked_add(word.len()).ok_or(JsonError::Syntax)?;
        if self.s.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(v)
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        match self.peek().ok_or(JsonError::Syntax)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.lit(b"true", Json::Bool(true)),
            b'f' => self.lit(b"false", Json::Bool(false)),
            b'n' => self.lit(b"null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn enter(depth: usize) -> Result<usize, JsonError> {
        let d = depth.checked_add(1).ok_or(JsonError::Depth)?;
        if d > MAX_DEPTH {
            Err(JsonError::Depth)
        } else {
            Ok(d)
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, JsonError> {
        let inner = Self::enter(depth)?;
        self.bump()?;
        let mut members: Vec<(String, Json)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.bump()?;
            return Ok(Json::Object(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            let k = self.string()?;
            if members.iter().any(|(m, _)| *m == k) {
                return Err(JsonError::Duplicate);
            }
            self.ws();
            if self.bump()? != b':' {
                return Err(JsonError::Syntax);
            }
            self.ws();
            let v = self.value(inner)?;
            members.push((k, v));
            self.ws();
            match self.bump()? {
                b',' => {}
                b'}' => return Ok(Json::Object(members)),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, JsonError> {
        let inner = Self::enter(depth)?;
        self.bump()?;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.bump()?;
            return Ok(Json::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(inner)?);
            self.ws();
            match self.bump()? {
                b',' => {}
                b']' => return Ok(Json::Array(items)),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.bump()?;
        }
        match self.bump()? {
            b'0' => {}
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.bump()?;
                }
            }
            _ => return Err(JsonError::Syntax),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E' | b'0'..=b'9')) {
            return Err(JsonError::Number);
        }
        let digits = self.s.get(start..self.pos).ok_or(JsonError::Syntax)?;
        let text = core::str::from_utf8(digits).map_err(|_| JsonError::Syntax)?;
        if text == "-0" {
            return Err(JsonError::Number);
        }
        text.parse::<i64>()
            .map(Json::Int)
            .map_err(|_| JsonError::Number)
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut v = 0_u32;
        for _ in 0..4 {
            let d = char::from(self.bump()?)
                .to_digit(16)
                .ok_or(JsonError::Syntax)?;
            v = v
                .checked_mul(16)
                .and_then(|x| x.checked_add(d))
                .ok_or(JsonError::Syntax)?;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.bump()?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos = self.pos.checked_add(1).ok_or(JsonError::Syntax)?;
            }
            let run = self.s.get(start..self.pos).ok_or(JsonError::Syntax)?;
            out.push_str(core::str::from_utf8(run).map_err(|_| JsonError::Utf8)?);
            match self.bump()? {
                b'"' => return Ok(out),
                b'\\' => {
                    let c = match self.bump()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.escape()?,
                        _ => return Err(JsonError::Syntax),
                    };
                    out.push(c);
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        let hi = self.hex4()?;
        let code = if (0xd800..0xdc00).contains(&hi) {
            if self.bump()? != b'\\' || self.bump()? != b'u' {
                return Err(JsonError::Syntax);
            }
            let lo = self.hex4()?;
            if !(0xdc00..0xe000).contains(&lo) {
                return Err(JsonError::Syntax);
            }
            hi.checked_sub(0xd800)
                .and_then(|h| h.checked_mul(0x400))
                .and_then(|h| h.checked_add(lo.checked_sub(0xdc00)?))
                .and_then(|c| c.checked_add(0x1_0000))
                .ok_or(JsonError::Syntax)?
        } else if (0xdc00..0xe000).contains(&hi) {
            return Err(JsonError::Syntax);
        } else {
            hi
        };
        char::from_u32(code).ok_or(JsonError::Syntax)
    }
}

/// Why base64url input is rejected (CR-56 row 18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not canonical unpadded base64url")]
pub struct Base64Error;

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => c.checked_sub(b'A'),
        b'a'..=b'z' => c.checked_sub(b'a').and_then(|x| x.checked_add(26)),
        b'0'..=b'9' => c.checked_sub(b'0').and_then(|x| x.checked_add(52)),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes unpadded base64url; padding, other alphabets and non-zero trailing bits are rejected.
///
/// # Errors
/// [`Base64Error`].
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks(4) {
        let mut acc = 0_u32;
        for &c in chunk {
            acc = acc.wrapping_shl(6) | u32::from(sextet(c).ok_or(Base64Error)?);
        }
        let (n, unused) = match chunk.len() {
            4 => (3, 0_u32),
            3 => (2, 2),
            2 => (1, 4),
            _ => return Err(Base64Error),
        };
        if acc & !u32::MAX.wrapping_shl(unused) != 0 {
            return Err(Base64Error);
        }
        let be = acc.wrapping_shr(unused).to_be_bytes();
        out.extend(be.iter().skip(4_usize.checked_sub(n).ok_or(Base64Error)?));
    }
    Ok(out)
}

/// Encodes unpadded base64url.
#[must_use]
pub fn b64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut buf = [0_u8; 4];
        for (d, s) in buf.iter_mut().skip(1).zip(chunk) {
            *d = *s;
        }
        let n = u32::from_be_bytes(buf);
        for shift in [18_u32, 12, 6, 0]
            .into_iter()
            .take(chunk.len().checked_add(1).unwrap_or(0))
        {
            let idx = usize::try_from(n.wrapping_shr(shift) & 0x3f).unwrap_or(0);
            if let Some(&c) = ALPHABET.get(idx) {
                out.push(char::from(c));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
