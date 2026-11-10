//! A cursor over the bounded DER reader of `access-parse` that also yields each element's whole
//! encoding, and the few DER encodings an OCSP request needs (CR-10).

use core::fmt::Write as _;

use access_parse::der::{DerError, Reader};

pub(crate) use access_parse::der::{BOOLEAN, INTEGER, OCTET_STRING, OID, SEQUENCE};

/// `BIT STRING`.
pub(crate) const BIT_STRING: u8 = 0x03;
/// `ENUMERATED`.
pub(crate) const ENUMERATED: u8 = 0x0a;
/// `NULL`.
pub(crate) const NULL: u8 = 0x05;
/// `UTF8String`.
pub(crate) const UTF8_STRING: u8 = 0x0c;
/// `UTCTime`.
pub(crate) const UTC_TIME: u8 = 0x17;
/// `GeneralizedTime`.
pub(crate) const GENERALIZED_TIME: u8 = 0x18;

/// One element: its tag, contents and whole encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Element<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
    pub(crate) whole: &'a [u8],
}

/// The header length of an element of `len` content octets in the shortest form, which is the
/// only form [`Reader`] accepts.
fn header_len(len: usize) -> usize {
    if len < 0x80 {
        2
    } else if len <= 0xff {
        3
    } else {
        4
    }
}

/// A cursor over consecutive elements of at most 8 KB.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cursor<'a> {
    input: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Result<Self, DerError> {
        Reader::new(input)?;
        Ok(Self { input })
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    pub(crate) fn next(&mut self) -> Result<Element<'a>, DerError> {
        let tlv = Reader::new(self.input)?.next_tlv()?;
        let n = header_len(tlv.value.len())
            .checked_add(tlv.value.len())
            .ok_or(DerError::Encoding)?;
        let whole = self.input.get(..n).ok_or(DerError::Truncated)?;
        self.input = self.input.get(n..).ok_or(DerError::Truncated)?;
        Ok(Element {
            tag: tlv.tag,
            value: tlv.value,
            whole,
        })
    }

    pub(crate) fn tagged(&mut self, tag: u8) -> Result<Element<'a>, DerError> {
        let e = self.next()?;
        if e.tag == tag {
            Ok(e)
        } else {
            Err(DerError::Tag)
        }
    }

    /// The next element when it carries `tag`; nothing is consumed otherwise.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<Element<'a>>, DerError> {
        if self.input.first() == Some(&tag) {
            self.next().map(Some)
        } else {
            Ok(None)
        }
    }

    /// The contents of the single element in `value`, which must carry `tag`.
    pub(crate) fn only(value: &'a [u8], tag: u8) -> Result<Element<'a>, DerError> {
        let mut c = Self::new(value)?;
        let e = c.tagged(tag)?;
        if c.is_empty() {
            Ok(e)
        } else {
            Err(DerError::Encoding)
        }
    }
}

/// The contents of a `BIT STRING` with no unused bits.
pub(crate) fn bits(value: &[u8]) -> Result<&[u8], DerError> {
    match value.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(DerError::Encoding),
    }
}

/// `OBJECT IDENTIFIER` contents in dotted form; `None` when malformed.
#[must_use]
pub(crate) fn dotted(oid: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut arc: u64 = 0;
    let mut first = true;
    let mut pending = false;
    for &b in oid {
        if !pending && b == 0x80 {
            return None;
        }
        arc = arc.checked_mul(128)?.checked_add(u64::from(b & 0x7f))?;
        pending = b & 0x80 != 0;
        if pending {
            continue;
        }
        if first {
            let (a, b) = match arc {
                0..=39 => (0, arc),
                40..=79 => (1, arc.checked_sub(40)?),
                _ => (2, arc.checked_sub(80)?),
            };
            let _ = write!(out, "{a}.{b}");
            first = false;
        } else {
            let _ = write!(out, ".{arc}");
        }
        arc = 0;
    }
    (!pending && !first).then_some(out)
}

/// The DER encoding of one element.
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>, DerError> {
    let len = value.len();
    let mut out = Vec::with_capacity(len.checked_add(4).ok_or(DerError::InputTooLarge)?);
    out.push(tag);
    if len < 0x80 {
        out.push(u8::try_from(len).map_err(|_| DerError::InputTooLarge)?);
    } else if let Ok(b) = u8::try_from(len) {
        out.extend([0x81, b]);
    } else {
        let two = u16::try_from(len).map_err(|_| DerError::InputTooLarge)?;
        out.push(0x82);
        out.extend(two.to_be_bytes());
    }
    out.extend_from_slice(value);
    Ok(out)
}

/// The DER encoding of a `SEQUENCE` of `parts`.
pub(crate) fn seq(parts: &[&[u8]]) -> Result<Vec<u8>, DerError> {
    tlv(SEQUENCE, &parts.concat())
}

/// Reads a definite length at the start of `input` (after the tag), up to four length octets,
/// for documents larger than the 8 KB reader takes; returns the length and the header size.
fn long_len(input: &[u8]) -> Option<(usize, usize)> {
    let (&first, rest) = input.split_first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return None;
    }
    let bytes = rest.get(..n)?;
    if bytes.first() == Some(&0) {
        return None;
    }
    let len = bytes.iter().try_fold(0_usize, |acc, b| {
        acc.checked_mul(256)?.checked_add(usize::from(*b))
    })?;
    Some((len, n.checked_add(1)?))
}

/// The contents of the element `tag` at the start of `input`, which may exceed 8 KB, and what
/// follows it.
pub(crate) fn long_tagged(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = input.split_first()?;
    if t != tag {
        return None;
    }
    let (len, header) = long_len(rest)?;
    let body = rest.get(header..)?;
    Some((body.get(..len)?, body.get(len..)?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // CR-10
    #[test]
    fn the_cursor_yields_whole_elements() {
        let input = [0x30, 0x03, 0x02, 0x01, 0x05, 0x04, 0x00];
        let mut c = Cursor::new(&input).unwrap();
        let e = c.tagged(SEQUENCE).unwrap();
        assert_eq!(e.whole, &input[..5]);
        assert_eq!(e.value, &[0x02, 0x01, 0x05]);
        assert_eq!(c.tagged(OCTET_STRING).unwrap().whole, &[0x04, 0x00]);
        assert!(c.is_empty());
        let big = vec![0_u8; 300];
        let enc = tlv(OCTET_STRING, &big).unwrap();
        let e = Cursor::new(&enc).unwrap().next().unwrap();
        assert_eq!(e.whole.len(), 304);
        assert!(Cursor::new(&vec![0_u8; 9000]).is_err());
    }

    #[test]
    fn oids_read_in_dotted_form() {
        assert_eq!(
            dotted(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]).unwrap(),
            "1.3.6.1.5.5.7.48.1"
        );
        assert_eq!(
            dotted(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x03, 0x07]).unwrap(),
            "2.16.840.1.101.3.2.1.3.7"
        );
        assert!(dotted(&[0x2b, 0x86]).is_none());
        assert!(dotted(&[0x2b, 0x80, 0x01]).is_none());
        assert!(dotted(&[]).is_none());
    }

    #[test]
    fn long_lengths_read_past_the_reader_ceiling() {
        let body = vec![1_u8; 70_000];
        let mut enc = vec![0x30, 0x83, 0x01, 0x11, 0x70];
        enc.extend_from_slice(&body);
        enc.push(0x05);
        let (value, rest) = long_tagged(&enc, SEQUENCE).unwrap();
        assert_eq!(value.len(), 70_000);
        assert_eq!(rest, &[0x05]);
        assert!(long_tagged(&[0x30, 0x81, 0x05], SEQUENCE).is_none());
        assert!(long_tagged(&[0x30, 0x85, 1, 1, 1, 1, 1], SEQUENCE).is_none());
    }
}
