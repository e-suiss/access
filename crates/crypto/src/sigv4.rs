//! AWS Signature Version 4 (OP-156 m.3 (s), (z)): the signing key a secret access key derives for
//! one day, region and service, and the signature of a string to sign. The canonical request and
//! the string to sign are the caller's; only the HMAC chain lives here (CR-13).

use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::dit::DitGuard;

fn mac(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(hmac::sign(&key, message).as_ref());
    out
}

/// The signature of `string_to_sign` under `secret` for `date` (`YYYYMMDD`), `region` and
/// `service`: `HMAC(kSigning, string_to_sign)` with
/// `kSigning = HMAC(HMAC(HMAC(HMAC("AWS4" ‖ secret, date), region), service), "aws4_request")`.
#[must_use]
pub fn signature(
    secret: &[u8],
    (date, region, service): (&str, &str, &str),
    string_to_sign: &str,
) -> [u8; 32] {
    // CR-39 m.6
    let _dit = DitGuard::new();
    let mut seed = Zeroizing::new(b"AWS4".to_vec());
    seed.extend_from_slice(secret);
    let k_date = mac(&seed, date.as_bytes());
    let k_region = mac(&*k_date, region.as_bytes());
    let k_service = mac(&*k_region, service.as_bytes());
    let k_signing = mac(&*k_service, b"aws4_request");
    *mac(&*k_signing, string_to_sign.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (s)
    #[test]
    fn the_signature_is_the_four_step_hmac_chain() {
        let secret = crate::random::bytes::<30>().unwrap();
        let one = |k: &[u8], m: &[u8]| {
            let key = hmac::Key::new(hmac::HMAC_SHA256, k);
            hmac::sign(&key, m).as_ref().to_vec()
        };
        let mut seed = b"AWS4".to_vec();
        seed.extend_from_slice(&secret);
        let k = one(&seed, b"20261110");
        let k = one(&k, b"eu-central-1");
        let k = one(&k, b"s3");
        let k = one(&k, b"aws4_request");
        let want = one(&k, b"AWS4-HMAC-SHA256\nx");
        let got = signature(
            &secret,
            ("20261110", "eu-central-1", "s3"),
            "AWS4-HMAC-SHA256\nx",
        );
        assert_eq!(got.as_slice(), want.as_slice());
        assert_ne!(
            signature(
                &secret,
                ("20261111", "eu-central-1", "s3"),
                "AWS4-HMAC-SHA256\nx"
            ),
            got
        );
    }
}
