#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

// TN-86, OP-153 m.19 (d), m.25 (i)
#[test]
fn a_bundle_opens_only_with_its_key_salt_and_additional_data() {
    let r = RecipientKey::generate().unwrap();
    let public = r.public().unwrap();
    assert_eq!(public.len(), KEY_LEN);
    let mut salt = <[u8; 32]>::default();
    rand::fill(&mut salt).unwrap();
    let s = Sealer::new(&public, &salt).unwrap();
    let (epk, nonce) = (s.epk().to_vec(), s.nonce());
    let ct = s.seal(b"aad", b"lines").unwrap();
    assert_eq!(r.open((&epk, &salt), nonce, b"aad", &ct).unwrap(), b"lines");
    assert_eq!(
        r.open((&epk, &salt), nonce, b"other", &ct),
        Err(BundleError::Open)
    );
    assert_eq!(
        r.open((&epk, &[8; 32]), nonce, b"aad", &ct),
        Err(BundleError::Open)
    );
    let other = RecipientKey::generate().unwrap();
    assert_eq!(
        other.open((&epk, &salt), nonce, b"aad", &ct),
        Err(BundleError::Open)
    );
    assert_eq!(
        Sealer::new(&public[..33], &salt).err(),
        Some(BundleError::Key)
    );
}
