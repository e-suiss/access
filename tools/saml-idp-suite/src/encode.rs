//! The encodings of the SAML bindings: base64 (POST), raw DEFLATE with stored blocks and
//! percent-encoding (HTTP-Redirect).

use std::fmt::Write as _;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
#[must_use]
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for k in 0..4_usize {
            if k <= chunk.len() {
                let shift =
                    18_u32.saturating_sub(6_u32.saturating_mul(u32::try_from(k).unwrap_or(0)));
                let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64, whitespace ignored; `None` when malformed.
#[must_use]
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((text.len() / 4).saturating_mul(3));
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    let mut padding = false;
    for c in text.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding = true;
            continue;
        }
        if padding {
            return None;
        }
        let v = u32::try_from(ALPHABET.iter().position(|&a| a == c)?).ok()?;
        acc = (acc << 6) | v;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Raw DEFLATE (RFC 1951) made of stored blocks: valid input for any inflater.
#[must_use]
pub fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().saturating_add(16));
    let mut chunks = data.chunks(0xffff).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
        return out;
    }
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let len = u16::try_from(chunk.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
#[must_use]
pub fn percent(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The `SAMLRequest` value of the HTTP-Redirect binding for `xml`.
#[must_use]
pub fn redirect_value(xml: &str) -> String {
    percent(&b64_encode(&deflate_stored(xml.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(b64_decode(&b64_encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert!(b64_decode("Zm9v!").is_none());
    }

    #[test]
    fn stored_deflate_frames_every_block() {
        let d = deflate_stored(b"abc");
        assert_eq!(d, [1, 3, 0, 0xfc, 0xff, b'a', b'b', b'c']);
        let big = vec![7_u8; 70_000];
        let d = deflate_stored(&big);
        assert_eq!(d.first(), Some(&0));
        assert_eq!(d.len(), 70_000 + 10);
    }

    #[test]
    fn percent_keeps_unreserved() {
        assert_eq!(percent("a+b/c=~"), "a%2Bb%2Fc%3D~");
    }
}
