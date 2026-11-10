//! The small BER subset an LDAP pull client needs (RFC 4511 §5.1): definite lengths only, one
//! message at most 256 KiB, read before it is allocated. Elements are walked one level at a time,
//! never recursively (OP-125, GHSA-qcxq-75wr-5cm8).

/// Largest message the client reads.
pub const MAX_MESSAGE: usize = 256 * 1024;

/// Why a message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BerError {
    /// Not well-formed, or not the element the protocol puts here.
    #[error("malformed BER")]
    Malformed,
    /// Larger than [`MAX_MESSAGE`].
    #[error("BER message too large")]
    TooLarge,
}

/// One element: its tag byte and its content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier octet (single-byte tags only).
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
}

/// Reads elements one after another.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

fn length(b: &[u8]) -> Result<Option<(usize, usize)>, BerError> {
    let Some(&first) = b.first() else {
        return Ok(None);
    };
    if first & 0x80 == 0 {
        return Ok(Some((1, usize::from(first))));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return Err(BerError::Malformed);
    }
    let Some(bytes) = b.get(1..=n) else {
        return Ok(None);
    };
    let len = bytes.iter().try_fold(0_usize, |acc, x| {
        acc.checked_mul(256)
            .and_then(|a| a.checked_add(usize::from(*x)))
            .ok_or(BerError::TooLarge)
    })?;
    Ok(Some((n.saturating_add(1), len)))
}

/// The total length of the message that starts `buf`, once its header is in; `None` until then.
///
/// # Errors
/// [`BerError`] for anything but a SEQUENCE, or a message above [`MAX_MESSAGE`].
pub fn frame_len(buf: &[u8]) -> Result<Option<usize>, BerError> {
    match buf.first() {
        None => return Ok(None),
        Some(&0x30) => {}
        Some(_) => return Err(BerError::Malformed),
    }
    let Some((head, len)) = length(buf.get(1..).unwrap_or_default())? else {
        return Ok(None);
    };
    let total = head
        .checked_add(1)
        .and_then(|h| h.checked_add(len))
        .ok_or(BerError::TooLarge)?;
    if total > MAX_MESSAGE {
        return Err(BerError::TooLarge);
    }
    Ok(Some(total))
}

impl<'a> Reader<'a> {
    /// A reader over `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// Whether every element was read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The next element.
    ///
    /// # Errors
    /// [`BerError::Malformed`].
    pub fn element(&mut self) -> Result<Tlv<'a>, BerError> {
        let (&tag, after) = self.rest.split_first().ok_or(BerError::Malformed)?;
        if tag & 0x1f == 0x1f {
            return Err(BerError::Malformed);
        }
        let (head, len) = length(after)?.ok_or(BerError::Malformed)?;
        let end = head.checked_add(len).ok_or(BerError::Malformed)?;
        let content = after.get(head..end).ok_or(BerError::Malformed)?;
        self.rest = after.get(end..).unwrap_or_default();
        Ok(Tlv { tag, content })
    }

    /// The next element, which must carry `tag`.
    ///
    /// # Errors
    /// [`BerError::Malformed`].
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], BerError> {
        let t = self.element()?;
        if t.tag == tag {
            Ok(t.content)
        } else {
            Err(BerError::Malformed)
        }
    }
}

/// A non-negative INTEGER's value.
///
/// # Errors
/// [`BerError::Malformed`].
pub fn integer(content: &[u8]) -> Result<u64, BerError> {
    if content.is_empty() || content.len() > 8 || content.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(BerError::Malformed);
    }
    Ok(content
        .iter()
        .fold(0_u64, |acc, b| (acc << 8) | u64::from(*b)))
}

/// Encodes one element.
#[must_use]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let used = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(used.len()).unwrap_or(4));
        out.extend_from_slice(used);
    }
    out.extend_from_slice(content);
    out
}

/// Encodes an INTEGER.
#[must_use]
pub fn int(tag: u8, n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take(7).take_while(|b| **b == 0).count();
    let mut v = bytes.get(skip..).unwrap_or_default().to_vec();
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        v.insert(0, 0);
    }
    tlv(tag, &v)
}

/// Concatenates encoded elements.
#[must_use]
pub fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-125
    #[test]
    fn lengths_are_read_before_bodies() {
        assert_eq!(frame_len(&[0x30, 0x03]), Ok(Some(5)));
        assert_eq!(
            frame_len(&[0x30, 0x84, 0x7f, 0, 0, 0]),
            Err(BerError::TooLarge)
        );
        assert_eq!(frame_len(&[0x04, 0x00]), Err(BerError::Malformed));
        let enc = tlv(0x04, &[7; 300]);
        let mut r = Reader::new(&enc);
        assert_eq!(r.expect(0x04).unwrap().len(), 300);
        assert!(r.is_empty());
        assert_eq!(integer(&int(0x02, 128)[2..]).unwrap(), 128);
        assert_eq!(integer(&int(0x02, 0)[2..]).unwrap(), 0);
    }
}
