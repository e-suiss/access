//! The base64 spellings imported hashes use: RFC 4648 standard and URL-safe, passlib's
//! adapted alphabet (`.` for `+`), padded or not, and bcrypt's own alphabet.

const BCRYPT: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn lenient(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(c.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(c.wrapping_sub(b'0').wrapping_add(52)),
        b'+' | b'.' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn bcrypt_value(c: u8) -> Option<u8> {
    BCRYPT
        .iter()
        .position(|a| *a == c)
        .and_then(|p| u8::try_from(p).ok())
}

fn decode_with(text: &str, value: fn(u8) -> Option<u8>) -> Option<Vec<u8>> {
    let body = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(body.len().saturating_mul(3) / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in body.bytes() {
        acc = acc.wrapping_shl(6) | u32::from(value(c)?);
        bits = bits.wrapping_add(6);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push(u8::try_from(acc.wrapping_shr(bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Decodes any of the RFC 4648 or passlib spellings; `None` on a foreign character.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
    decode_with(text, lenient)
}

/// Decodes bcrypt's alphabet.
pub(super) fn decode_bcrypt(text: &str) -> Option<Vec<u8>> {
    decode_with(text, bcrypt_value)
}

/// Encodes in bcrypt's alphabet without padding.
pub(super) fn encode_bcrypt(data: &[u8]) -> String {
    encode_with(data, BCRYPT)
}

/// The RFC 4648 standard alphabet.
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes in the RFC 4648 standard alphabet without padding, as PHC strings do.
pub(super) fn encode_standard(data: &[u8]) -> String {
    encode_with(data, STANDARD)
}

fn encode_with(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::with_capacity((data.len().saturating_mul(4) / 3).saturating_add(1));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut push = |v: u32| {
        let i = usize::try_from(v & 0x3f).unwrap_or(0);
        out.push(char::from(alphabet.get(i).copied().unwrap_or(b'.')));
    };
    for b in data {
        acc = acc.wrapping_shl(8) | u32::from(*b);
        bits = bits.wrapping_add(8);
        while bits >= 6 {
            bits = bits.wrapping_sub(6);
            push(acc.wrapping_shr(bits));
        }
    }
    if bits > 0 {
        push(acc.wrapping_shl(6u32.wrapping_sub(bits)));
    }
    out
}
