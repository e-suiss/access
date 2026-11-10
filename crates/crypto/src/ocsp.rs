//! The OCSP `CertID` digest (RFC 6960 §4.1.1, RFC 5019 §2.1.1): SHA-1 names a certificate in an
//! OCSP request and answer; it verifies and signs nothing (OP-155 m.3 (m)).

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};

/// SHA-1 of `data`, for a `CertID` only.
#[must_use]
pub fn cert_id_sha1(data: &[u8]) -> [u8; 20] {
    let d = digest(&SHA1_FOR_LEGACY_USE_ONLY, data);
    let mut out = [0_u8; 20];
    for (o, b) in out.iter_mut().zip(d.as_ref()) {
        *o = *b;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 3174 §7.3
    #[test]
    fn it_is_sha1() {
        assert_eq!(
            cert_id_sha1(b"abc").get(..4),
            Some(&[0xa9, 0x99, 0x3e, 0x36][..])
        );
    }
}
