//! Bounded DER reader for X.509 fields that certificate path validation does not expose
//! (CR-10: x509/DER ≤ 8 KB). Definite lengths only, in their shortest form; nothing is
//! allocated.

/// Ceiling for one DER input (CR-10 m.3).
pub const MAX_INPUT: usize = 8 * 1024;

/// `SEQUENCE`.
pub const SEQUENCE: u8 = 0x30;
/// `SET`.
pub const SET: u8 = 0x31;
/// `OBJECT IDENTIFIER`.
pub const OID: u8 = 0x06;
/// `BOOLEAN`.
pub const BOOLEAN: u8 = 0x01;
/// `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;

/// Why DER input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DerError {
    /// Larger than [`MAX_INPUT`].
    #[error("input too large")]
    InputTooLarge,
    /// The input ended inside an element.
    #[error("truncated input")]
    Truncated,
    /// Indefinite, non-minimal or oversized length, or a multi-byte tag.
    #[error("non-canonical encoding")]
    Encoding,
    /// A different tag than expected.
    #[error("unexpected tag")]
    Tag,
}

/// One element: its tag byte and contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The single tag byte.
    pub tag: u8,
    /// The contents octets.
    pub value: &'a [u8],
}

/// A cursor over consecutive elements.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `input`, which must not exceed [`MAX_INPUT`].
    ///
    /// # Errors
    /// [`DerError::InputTooLarge`].
    pub fn new(input: &'a [u8]) -> Result<Self, DerError> {
        if input.len() > MAX_INPUT {
            Err(DerError::InputTooLarge)
        } else {
            Ok(Self { rest: input })
        }
    }

    /// Whether every element was read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next element.
    ///
    /// # Errors
    /// [`DerError`].
    pub fn next_tlv(&mut self) -> Result<Tlv<'a>, DerError> {
        let (&tag, rest) = self.rest.split_first().ok_or(DerError::Truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(DerError::Encoding);
        }
        let (&first, mut rest) = rest.split_first().ok_or(DerError::Truncated)?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 2 {
                return Err(DerError::Encoding);
            }
            let (bytes, after) = (rest.get(..n), rest.get(n..));
            let (bytes, after) = (
                bytes.ok_or(DerError::Truncated)?,
                after.ok_or(DerError::Truncated)?,
            );
            rest = after;
            let len = bytes
                .iter()
                .fold(0_usize, |acc, b| acc.wrapping_shl(8) | usize::from(*b));
            if len < 0x80 || bytes.first() == Some(&0) {
                return Err(DerError::Encoding);
            }
            len
        };
        let value = rest.get(..len).ok_or(DerError::Truncated)?;
        self.rest = rest.get(len..).ok_or(DerError::Truncated)?;
        Ok(Tlv { tag, value })
    }

    /// The next element, which must carry `tag`.
    ///
    /// # Errors
    /// [`DerError`].
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], DerError> {
        let tlv = self.next_tlv()?;
        if tlv.tag == tag {
            Ok(tlv.value)
        } else {
            Err(DerError::Tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-10
    #[test]
    fn reads_canonical_lengths_only() {
        let mut r = Reader::new(&[0x30, 0x03, 0x02, 0x01, 0x05, 0x04, 0x00]).unwrap();
        assert_eq!(r.expect(SEQUENCE).unwrap(), &[0x02, 0x01, 0x05]);
        assert_eq!(r.expect(OCTET_STRING).unwrap(), &[] as &[u8]);
        assert!(r.is_empty());
        assert_eq!(
            Reader::new(&[0x04, 0x81, 0x01, 0x00]).unwrap().next_tlv(),
            Err(DerError::Encoding)
        );
        assert_eq!(
            Reader::new(&[0x04, 0x80]).unwrap().next_tlv(),
            Err(DerError::Encoding)
        );
        assert_eq!(
            Reader::new(&[0x04, 0x05, 0x00]).unwrap().next_tlv(),
            Err(DerError::Truncated)
        );
        assert_eq!(
            Reader::new(&[0x1f, 0x01, 0x00]).unwrap().next_tlv(),
            Err(DerError::Encoding)
        );
        assert_eq!(
            Reader::new(&[0x02, 0x00]).unwrap().expect(SEQUENCE),
            Err(DerError::Tag)
        );
        let long = [0_u8; MAX_INPUT + 1];
        assert!(Reader::new(&long).is_err());
        let mut big = vec![0x04, 0x82, 0x01, 0x00];
        big.extend([7; 256]);
        assert_eq!(
            Reader::new(&big)
                .unwrap()
                .expect(OCTET_STRING)
                .unwrap()
                .len(),
            256
        );
    }
}
