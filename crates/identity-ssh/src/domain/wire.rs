//! The SSH wire encoding (RFC 4251 §5): `uint32`, `uint64`, `string` and the packed string
//! lists of certificates, written into a buffer and read back with a bounded cursor.

use crate::SshError;

/// Largest field one string may carry while reading (a certificate is far smaller).
pub const MAX_STRING: usize = 16 * 1024;

/// A growing SSH wire buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self { out: Vec::new() }
    }

    /// One byte.
    pub fn byte(&mut self, b: u8) -> &mut Self {
        self.out.push(b);
        self
    }

    /// A big-endian `uint32`.
    pub fn u32(&mut self, n: u32) -> &mut Self {
        self.out.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// A big-endian `uint64`.
    pub fn u64(&mut self, n: u64) -> &mut Self {
        self.out.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// Raw bytes, without a length.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.out.extend_from_slice(bytes);
        self
    }

    /// A `string`: a `uint32` length and the bytes.
    ///
    /// # Errors
    /// [`SshError::TooLarge`] past 4 GiB.
    pub fn string(&mut self, bytes: &[u8]) -> Result<&mut Self, SshError> {
        let len = u32::try_from(bytes.len()).map_err(|_| SshError::TooLarge)?;
        self.u32(len);
        self.out.extend_from_slice(bytes);
        Ok(self)
    }

    /// The bytes written so far.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.out
    }

    /// The buffer.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// `strings` packed one after another, each as a `string` (the certificate's principal list).
///
/// # Errors
/// [`SshError::TooLarge`].
pub fn packed<'a>(strings: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<u8>, SshError> {
    let mut w = Writer::new();
    for s in strings {
        w.string(s)?;
    }
    Ok(w.finish())
}

/// A bounded cursor over SSH wire data.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A cursor at the start of `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    /// Whether every byte was read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// What remains.
    #[must_use]
    pub const fn rest(&self) -> &'a [u8] {
        self.rest
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SshError> {
        if n > self.rest.len() {
            return Err(SshError::Malformed);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    /// One byte.
    ///
    /// # Errors
    /// [`SshError::Malformed`] at the end.
    pub fn byte(&mut self) -> Result<u8, SshError> {
        self.take(1)?.first().copied().ok_or(SshError::Malformed)
    }

    /// A `uint32`.
    ///
    /// # Errors
    /// [`SshError::Malformed`].
    pub fn u32(&mut self) -> Result<u32, SshError> {
        let b = <[u8; 4]>::try_from(self.take(4)?).map_err(|_| SshError::Malformed)?;
        Ok(u32::from_be_bytes(b))
    }

    /// A `uint64`.
    ///
    /// # Errors
    /// [`SshError::Malformed`].
    pub fn u64(&mut self) -> Result<u64, SshError> {
        let b = <[u8; 8]>::try_from(self.take(8)?).map_err(|_| SshError::Malformed)?;
        Ok(u64::from_be_bytes(b))
    }

    /// `n` raw bytes.
    ///
    /// # Errors
    /// [`SshError::Malformed`].
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], SshError> {
        self.take(n)
    }

    /// A `string` of at most [`MAX_STRING`] bytes.
    ///
    /// # Errors
    /// [`SshError::Malformed`]; [`SshError::TooLarge`].
    pub fn string(&mut self, max: usize) -> Result<&'a [u8], SshError> {
        let len = usize::try_from(self.u32()?).map_err(|_| SshError::TooLarge)?;
        if len > max.min(MAX_STRING) {
            return Err(SshError::TooLarge);
        }
        self.take(len)
    }

    /// A `string` holding UTF-8 text.
    ///
    /// # Errors
    /// [`SshError::Malformed`]; [`SshError::TooLarge`].
    pub fn text(&mut self, max: usize) -> Result<&'a str, SshError> {
        core::str::from_utf8(self.string(max)?).map_err(|_| SshError::Malformed)
    }
}

/// The strings packed in `data`, each at most `max` bytes, at most `count` of them.
///
/// # Errors
/// [`SshError::Malformed`]; [`SshError::TooLarge`].
pub fn unpacked(data: &[u8], max: usize, count: usize) -> Result<Vec<&[u8]>, SshError> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.is_empty() {
        if out.len() >= count {
            return Err(SshError::TooLarge);
        }
        out.push(r.string(max)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    #[test]
    fn strings_round_trip_and_bounds_hold() {
        let mut w = Writer::new();
        w.u32(7).u64(9).string(b"ssh").unwrap();
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u32().unwrap(), 7);
        assert_eq!(r.u64().unwrap(), 9);
        assert_eq!(r.string(8).unwrap(), b"ssh");
        assert!(r.is_empty());
        assert_eq!(Reader::new(&bytes).byte().unwrap(), 0);
        let mut short = Reader::new(&bytes[..14]);
        short.u32().unwrap();
        short.u64().unwrap();
        assert_eq!(short.string(8), Err(SshError::Malformed));
        let mut big = Reader::new(&bytes[12..]);
        assert_eq!(big.string(2), Err(SshError::TooLarge));
        let list = packed([&b"a"[..], b"bc"]).unwrap();
        assert_eq!(unpacked(&list, 4, 2).unwrap(), vec![&b"a"[..], b"bc"]);
        assert_eq!(unpacked(&list, 4, 1), Err(SshError::TooLarge));
    }
}
