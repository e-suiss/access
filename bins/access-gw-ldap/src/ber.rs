//! BER limits before any decoding (OP-155 m.3 (n), OP-125, GHSA-qcxq-75wr-5cm8): an `LDAPMessage`
//! is at most 256 KiB, its length is read from the header before the body is allocated, and its
//! nesting is checked to 32 levels by one pass over the bytes, without recursion, before the
//! codec builds anything.

/// Largest `LDAPMessage`.
pub const MAX_MESSAGE: usize = 256 * 1024;

/// Deepest nesting of constructed elements.
pub const MAX_DEPTH: usize = 32;

/// Why a message was refused before decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BerError {
    /// Not a definite-length SEQUENCE, or a length that does not fit its container.
    #[error("malformed BER")]
    Malformed,
    /// Larger than [`MAX_MESSAGE`].
    #[error("BER message too large")]
    TooLarge,
    /// Deeper than [`MAX_DEPTH`].
    #[error("BER nesting too deep")]
    TooDeep,
}

/// The header of one element at `at`: (tag is constructed, header length, content length).
fn header(b: &[u8], at: usize) -> Result<Option<(bool, usize, usize)>, BerError> {
    let Some(&tag) = b.get(at) else {
        return Ok(None);
    };
    let mut pos = at.checked_add(1).ok_or(BerError::Malformed)?;
    if tag & 0x1f == 0x1f {
        loop {
            let Some(&t) = b.get(pos) else {
                return Ok(None);
            };
            pos = pos.checked_add(1).ok_or(BerError::Malformed)?;
            if pos.saturating_sub(at) > 6 {
                return Err(BerError::Malformed);
            }
            if t & 0x80 == 0 {
                break;
            }
        }
    }
    let Some(&first) = b.get(pos) else {
        return Ok(None);
    };
    pos = pos.checked_add(1).ok_or(BerError::Malformed)?;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(if n == 0 {
                BerError::Malformed
            } else {
                BerError::TooLarge
            });
        }
        let mut len = 0_usize;
        for _ in 0..n {
            let Some(&x) = b.get(pos) else {
                return Ok(None);
            };
            pos = pos.checked_add(1).ok_or(BerError::Malformed)?;
            len = len
                .checked_mul(256)
                .and_then(|l| l.checked_add(usize::from(x)))
                .ok_or(BerError::TooLarge)?;
        }
        len
    };
    Ok(Some((tag & 0x20 != 0, pos.saturating_sub(at), len)))
}

/// The total length of the message that starts `buf`, once its header is complete: `None` until
/// then. Refuses anything but a SEQUENCE, and a message larger than [`MAX_MESSAGE`], before its
/// body arrives.
///
/// # Errors
/// [`BerError`].
pub fn frame_len(buf: &[u8]) -> Result<Option<usize>, BerError> {
    if buf.first().is_some_and(|&t| t != 0x30) {
        return Err(BerError::Malformed);
    }
    let Some((_, head, len)) = header(buf, 0)? else {
        return Ok(None);
    };
    let total = head.checked_add(len).ok_or(BerError::TooLarge)?;
    if total > MAX_MESSAGE {
        return Err(BerError::TooLarge);
    }
    Ok(Some(total))
}

/// Walks the whole message once: every element fits its container, and constructed elements nest
/// at most [`MAX_DEPTH`] deep. The walk keeps the end of each open container on a bounded stack.
///
/// # Errors
/// [`BerError`].
pub fn check(msg: &[u8]) -> Result<(), BerError> {
    if msg.len() > MAX_MESSAGE {
        return Err(BerError::TooLarge);
    }
    let mut ends: Vec<usize> = Vec::with_capacity(MAX_DEPTH);
    ends.push(msg.len());
    let mut at = 0_usize;
    while at < msg.len() {
        while ends.last().is_some_and(|&e| at >= e) {
            ends.pop();
        }
        let Some((constructed, head, len)) = header(msg, at)? else {
            return Err(BerError::Malformed);
        };
        let start = at.checked_add(head).ok_or(BerError::Malformed)?;
        let end = start.checked_add(len).ok_or(BerError::Malformed)?;
        if ends.last().is_none_or(|&outer| end > outer) {
            return Err(BerError::Malformed);
        }
        if constructed {
            if ends.len() > MAX_DEPTH {
                return Err(BerError::TooDeep);
            }
            ends.push(end);
            at = start;
        } else {
            at = end;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "test code"
    )]

    use super::*;

    fn nested(depth: usize) -> Vec<u8> {
        let mut inner = vec![0x04, 0x00];
        for _ in 0..depth {
            let mut next = vec![0x30];
            if inner.len() < 128 {
                next.push(u8::try_from(inner.len()).unwrap());
            } else {
                next.push(0x83);
                next.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_be_bytes()[1..]);
            }
            next.extend_from_slice(&inner);
            inner = next;
        }
        inner
    }

    // GHSA-qcxq-75wr-5cm8
    #[test]
    fn deep_nesting_is_refused_without_recursion() {
        assert_eq!(check(&nested(MAX_DEPTH)), Ok(()));
        assert_eq!(check(&nested(MAX_DEPTH + 1)), Err(BerError::TooDeep));
        let hostile = nested(20_000);
        assert!(hostile.len() < MAX_MESSAGE);
        assert_eq!(check(&hostile), Err(BerError::TooDeep));
    }

    // OP-155 m.3 (n), OP-125
    #[test]
    fn oversized_messages_are_refused_from_the_header() {
        assert_eq!(frame_len(&[0x30]), Ok(None));
        assert_eq!(frame_len(&[0x30, 0x03]), Ok(Some(5)));
        assert_eq!(
            frame_len(&[0x30, 0x83, 0x04, 0x00, 0x01]),
            Err(BerError::TooLarge)
        );
        assert_eq!(
            frame_len(&[0x30, 0x85, 1, 1, 1, 1, 1]),
            Err(BerError::TooLarge)
        );
        assert_eq!(frame_len(&[0x30, 0x80]), Err(BerError::Malformed));
        assert_eq!(frame_len(&[0x04, 0x00]), Err(BerError::Malformed));
        assert_eq!(
            check(&[0x30, 0x05, 0x04, 0x09, 0x00]),
            Err(BerError::Malformed)
        );
    }
}
