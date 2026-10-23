use alloc::vec::Vec;

use super::{EncodeError, Limits, Value};

/// Encodes a value canonically: shortest heads, map keys sorted by their encoding (RFC 8949 §4.2.1).
///
/// # Errors
/// Duplicate map keys, or a value outside `limits`.
pub fn encode(value: &Value, limits: Limits) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    write(&mut out, value, 0, limits)?;
    Ok(out)
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    let bytes = value.to_be_bytes();
    let (info, skip) = match value {
        0..=23 => (u8::try_from(value).unwrap_or(0), 8),
        24..=0xff => (24, 7),
        0x100..=0xffff => (25, 6),
        0x1_0000..=0xffff_ffff => (26, 4),
        _ => (27, 0),
    };
    out.push(m | info);
    out.extend(bytes.iter().skip(skip));
}

fn len(n: usize, cap: usize) -> Result<u64, EncodeError> {
    if n > cap {
        return Err(EncodeError::Limits);
    }
    u64::try_from(n).map_err(|_| EncodeError::Limits)
}

fn inner(depth: usize, limits: Limits) -> Result<usize, EncodeError> {
    let next = depth.checked_add(1).ok_or(EncodeError::Limits)?;
    if next > limits.depth {
        Err(EncodeError::Limits)
    } else {
        Ok(next)
    }
}

fn write(
    out: &mut Vec<u8>,
    value: &Value,
    depth: usize,
    limits: Limits,
) -> Result<(), EncodeError> {
    match value {
        Value::Unsigned(u) => head(out, 0, *u),
        Value::Negative(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, len(b.len(), limits.string)?);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, len(t.len(), limits.string)?);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, len(items.len(), limits.items)?);
            let d = inner(depth, limits)?;
            for item in items {
                write(out, item, d, limits)?;
            }
        }
        Value::Map(entries) => {
            head(out, 5, len(entries.len(), limits.items)?);
            let d = inner(depth, limits)?;
            let mut encoded = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut kb = Vec::new();
                write(&mut kb, k, d, limits)?;
                let mut vb = Vec::new();
                write(&mut vb, v, d, limits)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded
                .windows(2)
                .any(|w| matches!(w, [a, b] if a.0 == b.0))
            {
                return Err(EncodeError::DuplicateKey);
            }
            for (kb, vb) in encoded {
                out.extend_from_slice(&kb);
                out.extend_from_slice(&vb);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
    }
    Ok(())
}
