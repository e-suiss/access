use super::{
    CACHE_TTL_MS, Dek, DekCache, DekKek, EnvelopeError, Kek, Sealer, SoftKek, open_body, rewrap,
    seal_body,
};
use crate::secret::Secret;

fn kek(id: &str, b: u8) -> SoftKek {
    SoftKek::new(id, [b; 32])
}

// T39, CR-32
#[test]
fn a_body_opens_only_with_its_key_and_context() {
    let k = kek("domain-kek-1", 1);
    let dek = Dek::generate().unwrap();
    let wrapped = k.wrap(&dek).unwrap();
    assert_eq!(wrapped.len(), 40, "RFC 3394 adds one 8-byte block");
    let sealed = seal_body(dek, b"dom|body", b"secret body").unwrap();
    let dek = k.unwrap(&wrapped).unwrap();
    assert_eq!(
        open_body(&dek, b"dom|body", &sealed).unwrap().as_slice(),
        b"secret body"
    );
    assert_eq!(
        open_body(&dek, b"dom|other", &sealed).unwrap_err(),
        EnvelopeError::Open
    );
    let mut tampered = sealed.clone();
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        open_body(&dek, b"dom|body", &tampered).unwrap_err(),
        EnvelopeError::Open
    );
    let other = Dek::generate().unwrap();
    assert_eq!(
        open_body(&other, b"dom|body", &sealed).unwrap_err(),
        EnvelopeError::Open
    );
}

// OP-135 m.1
#[test]
fn wrapping_is_bound_to_the_kek_and_rotates() {
    let (old, new) = (kek("v1", 1), kek("v2", 2));
    let dek = Dek::generate().unwrap();
    let wrapped = old.wrap(&dek).unwrap();
    let sealed = seal_body(dek, b"c", b"x").unwrap();
    assert_eq!(new.unwrap(&wrapped).err(), Some(EnvelopeError::Wrap));
    let rotated = rewrap(&old, &new, &wrapped).unwrap();
    assert_ne!(rotated, wrapped);
    assert_eq!(
        open_body(&new.unwrap(&rotated).unwrap(), b"c", &sealed)
            .unwrap()
            .as_slice(),
        b"x"
    );
    let mut bad = wrapped.clone();
    bad[5] ^= 1;
    assert_eq!(old.unwrap(&bad).err(), Some(EnvelopeError::Wrap));
}

// V4 (CR-51.2)
#[test]
fn a_long_lived_key_stops_at_its_limit() {
    let mut s = Sealer::with_limit(Dek::generate().unwrap(), 0, 2);
    let a = s.seal(b"c", b"1").unwrap();
    s.seal(b"c", b"2").unwrap();
    assert_eq!(s.seal(b"c", b"3").unwrap_err(), EnvelopeError::Exhausted);
    assert_eq!(s.used(), 2);
    assert_eq!(s.open(b"c", &a).unwrap().as_slice(), b"1");
    let mut full = Sealer::with_limit(Dek::generate().unwrap(), u64::MAX, u64::MAX);
    assert_eq!(full.seal(b"c", b"x").unwrap_err(), EnvelopeError::Exhausted);
    assert_eq!(
        Sealer::new(Dek::generate().unwrap(), super::MESSAGE_LIMIT)
            .seal(b"c", b"x")
            .unwrap_err(),
        EnvelopeError::Exhausted
    );
}

#[test]
fn nonces_are_fresh() {
    let mut s = Sealer::new(Dek::generate().unwrap(), 0);
    let (a, b) = (s.seal(b"c", b"m").unwrap(), s.seal(b"c", b"m").unwrap());
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}

// CR-32.2
#[test]
fn the_cache_expires_bounds_and_forgets() {
    let k = kek("v1", 1);
    let wrapped: Vec<Vec<u8>> = (0..3)
        .map(|_| k.wrap(&Dek::generate().unwrap()).unwrap())
        .collect();
    let mut c = DekCache::new(CACHE_TTL_MS, 2);
    c.get(&k, &wrapped[0], 0).unwrap();
    c.get(&k, &wrapped[1], 10).unwrap();
    c.get(&k, &wrapped[2], 20).unwrap();
    assert_eq!(c.len(), 2, "the oldest entry made room");
    c.forget(&wrapped[2]);
    assert_eq!(c.len(), 1);
    c.get(&k, &wrapped[1], CACHE_TTL_MS + 11).unwrap();
    assert_eq!(
        c.len(),
        1,
        "the expired entry was dropped and the key unwrapped again"
    );
    assert!(c.get(&kek("v2", 2), &wrapped[0], 0).is_err());
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0_u8; N];
    for (b, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *b = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out
}

fn dek(bytes: [u8; 32]) -> Dek {
    Dek::from_secret(Secret::new(bytes))
}

// OP-135 m.1, §4.6
// §4.3
#[test]
fn a_dek_wraps_like_rfc_3394() {
    let kek_bytes = hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let data = hex::<32>("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
    let wrapped = hex::<40>(
        "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
    );
    let class = dek(kek_bytes);
    let k = DekKek::new("class-1", &class);
    assert_eq!(k.id(), "class-1");
    assert_eq!(k.wrap(&dek(data)).unwrap(), wrapped);
    assert_eq!(*k.unwrap(&wrapped).unwrap().secret().expose(), data);
    assert_eq!(
        SoftKek::new("v1", kek_bytes).wrap(&dek(data)).unwrap(),
        wrapped
    );
    let short = hex::<24>("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7");
    assert_eq!(k.unwrap(&short).err(), Some(EnvelopeError::Wrap));
    for bad in [&wrapped[..39], &wrapped[..0], &[0_u8; 48][..]] {
        assert_eq!(k.unwrap(bad).err(), Some(EnvelopeError::Wrap));
    }
}

// CR-32, OP-74
#[test]
fn a_class_dek_wraps_part_deks() {
    let (old, new) = (kek("v1", 1), kek("v2", 2));
    let class = Dek::generate().unwrap();
    let class_wrapped = old.wrap(&class).unwrap();
    let part = Dek::generate().unwrap();
    let part_wrapped = DekKek::new("class", &class).wrap(&part).unwrap();
    assert_eq!(part_wrapped.len(), 40);
    let sealed = seal_body(part, b"part", b"body part").unwrap();
    drop(class);
    let class_wrapped = rewrap(&old, &new, &class_wrapped).unwrap();
    let class = new.unwrap(&class_wrapped).unwrap();
    let part = DekKek::new("class", &class).unwrap(&part_wrapped).unwrap();
    assert_eq!(
        open_body(&part, b"part", &sealed).unwrap().as_slice(),
        b"body part"
    );
    let other = Dek::generate().unwrap();
    assert_eq!(
        DekKek::new("class", &other).unwrap(&part_wrapped).err(),
        Some(EnvelopeError::Wrap)
    );
    let mut bad = part_wrapped.clone();
    bad[0] ^= 1;
    assert_eq!(
        DekKek::new("class", &class).unwrap(&bad).err(),
        Some(EnvelopeError::Wrap)
    );
}
