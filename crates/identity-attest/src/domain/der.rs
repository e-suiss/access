//! Bounded DER reader for the certificate extensions attestation formats carry (CR-10):
//! definite, shortest-form lengths only; high tag numbers up to three bytes, which Android's
//! `AuthorizationList` uses; nothing is allocated.

/// Ceiling for one DER input (CR-10, PD): a certificate or an extension.
pub(crate) const MAX_INPUT: usize = 16 * 1024;

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OID: u8 = 0x06;
pub(crate) const ENUMERATED: u8 = 0x0a;
pub(crate) const SEQUENCE: u8 = 0x30;

/// Why DER input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DerError;

/// A tag: its first octet (class, constructed bit and, for a low tag, the number) and its
/// number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tag {
    pub(crate) first: u8,
    pub(crate) number: u32,
}

impl Tag {
    /// Whether it is the single-octet tag `byte`.
    pub(crate) const fn is(self, byte: u8) -> bool {
        self.first == byte && self.first & 0x1f != 0x1f
    }

    /// Whether it is the context-specific tag `[number]`.
    pub(crate) const fn context(self, number: u32) -> bool {
        self.first & 0xc0 == 0x80 && self.number == number
    }
}

/// One element.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: Tag,
    pub(crate) value: &'a [u8],
}

/// A cursor over consecutive elements.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Result<Self, DerError> {
        if input.len() > MAX_INPUT {
            Err(DerError)
        } else {
            Ok(Self { rest: input })
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn tag(&mut self) -> Result<Tag, DerError> {
        let (&first, rest) = self.rest.split_first().ok_or(DerError)?;
        self.rest = rest;
        if first & 0x1f != 0x1f {
            return Ok(Tag {
                first,
                number: u32::from(first & 0x1f),
            });
        }
        let mut number = 0_u32;
        for i in 0..3 {
            let (&b, rest) = self.rest.split_first().ok_or(DerError)?;
            self.rest = rest;
            if i == 0 && b == 0x80 {
                return Err(DerError);
            }
            number = number.checked_mul(128).ok_or(DerError)? | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                if number < 31 {
                    return Err(DerError);
                }
                return Ok(Tag { first, number });
            }
        }
        Err(DerError)
    }

    pub(crate) fn next_tlv(&mut self) -> Result<Tlv<'a>, DerError> {
        let tag = self.tag()?;
        let (&first, mut rest) = self.rest.split_first().ok_or(DerError)?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 2 {
                return Err(DerError);
            }
            let bytes = rest.get(..n).ok_or(DerError)?;
            rest = rest.get(n..).ok_or(DerError)?;
            let len = bytes
                .iter()
                .fold(0_usize, |acc, b| acc.wrapping_shl(8) | usize::from(*b));
            if len < 0x80 || bytes.first() == Some(&0) {
                return Err(DerError);
            }
            len
        };
        let value = rest.get(..len).ok_or(DerError)?;
        self.rest = rest.get(len..).ok_or(DerError)?;
        Ok(Tlv { tag, value })
    }

    pub(crate) fn tagged(&mut self, byte: u8) -> Result<&'a [u8], DerError> {
        let tlv = self.next_tlv()?;
        if tlv.tag.is(byte) {
            Ok(tlv.value)
        } else {
            Err(DerError)
        }
    }

    /// The next element when it carries the single-octet tag `byte`; nothing is read otherwise.
    pub(crate) fn optional(&mut self, byte: u8) -> Result<Option<&'a [u8]>, DerError> {
        let mut peek = *self;
        match peek.next_tlv() {
            Ok(t) if t.tag.is(byte) => {
                *self = peek;
                Ok(Some(t.value))
            }
            Ok(_) => Ok(None),
            Err(_) if self.rest.is_empty() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A non-negative DER INTEGER of at most eight octets.
pub(crate) fn uint(value: &[u8]) -> Result<u64, DerError> {
    let body = match value {
        [0, rest @ ..] if rest.first().is_some_and(|b| b & 0x80 != 0) => rest,
        [b, ..] if b & 0x80 != 0 => return Err(DerError),
        [0, _, ..] => return Err(DerError),
        other => other,
    };
    if body.is_empty() || body.len() > 8 {
        return Err(DerError);
    }
    Ok(body
        .iter()
        .fold(0_u64, |acc, b| acc.wrapping_shl(8) | u64::from(*b)))
}

/// A DER BOOLEAN.
pub(crate) fn boolean(value: &[u8]) -> Result<bool, DerError> {
    match value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(DerError),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // CR-10
    #[test]
    fn high_tag_numbers_and_canonical_lengths() {
        let input = [0xbf, 0x85, 0x40, 0x03, 0x01, 0x01, 0xff];
        let mut r = Reader::new(&input).unwrap();
        let t = r.next_tlv().unwrap();
        assert!(t.tag.context(704));
        assert_eq!(t.value, &[0x01, 0x01, 0xff]);
        assert!(r.is_empty());
        for bad in [
            &[0xbf, 0x1e, 0x00][..],
            &[0xbf, 0x80, 0x01, 0x00],
            &[0x04, 0x81, 0x01, 0x00],
            &[0x04, 0x80],
            &[0x04, 0x02, 0x00],
        ] {
            assert!(Reader::new(bad).unwrap().next_tlv().is_err(), "{bad:?}");
        }
        assert!(Reader::new(&vec![0; MAX_INPUT + 1]).is_err());
        assert_eq!(uint(&[0x00, 0x80]).unwrap(), 128);
        assert!(uint(&[0x80]).is_err());
        assert!(uint(&[0x00, 0x01]).is_err());
        assert!(boolean(&[0x01]).is_err());
    }
}
