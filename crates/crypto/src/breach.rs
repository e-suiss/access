//! The breached-password range digest (IDP-3, OP-146 m.4 (e)): SHA-1, upper-case hex, as the
//! k-anonymity range protocol defines it. Nothing else may use SHA-1.

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};

use crate::dit::DitGuard;

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// The 40 upper-case hex characters of `SHA-1(password)`; the first five are the range prefix.
#[must_use]
pub fn range_digest(password: &[u8]) -> [u8; 40] {
    // CR-39 m.6
    let _dit = DitGuard::new();
    let d = digest(&SHA1_FOR_LEGACY_USE_ONLY, password);
    let mut out = [b'0'; 40];
    for ([hi, lo], b) in out.as_chunks_mut::<2>().0.iter_mut().zip(d.as_ref()) {
        *hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        *lo = HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0');
    }
    out
}

#[cfg(test)]
mod tests;
