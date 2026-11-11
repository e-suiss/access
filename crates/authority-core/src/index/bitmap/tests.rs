#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

fn lcg(seed: &mut u64) -> u32 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    u32::try_from(*seed >> 40).unwrap()
}

// §9.7A.1, CMP-9, Ek B 6126
#[test]
fn the_portable_form_of_a_small_set_is_the_roaring_layout() {
    let b: Bitmap = [1u32, 2, 65_536 + 7].into_iter().collect();
    let bytes = b.to_bytes();
    let mut want = Vec::new();
    want.extend_from_slice(&12_346u32.to_le_bytes());
    want.extend_from_slice(&2u32.to_le_bytes());
    want.extend_from_slice(&0u16.to_le_bytes());
    want.extend_from_slice(&1u16.to_le_bytes());
    want.extend_from_slice(&1u16.to_le_bytes());
    want.extend_from_slice(&0u16.to_le_bytes());
    want.extend_from_slice(&24u32.to_le_bytes());
    want.extend_from_slice(&28u32.to_le_bytes());
    for low in [1u16, 2, 7] {
        want.extend_from_slice(&low.to_le_bytes());
    }
    assert_eq!(bytes, want);
    assert_eq!(Bitmap::from_bytes(&bytes).unwrap(), b);
}

// §9.7A.1, CMP-9, Ek B 6126
#[test]
fn a_container_past_4096_values_becomes_a_bitmap_and_back() {
    let mut b = Bitmap::new();
    for v in 0..=u32::try_from(ARRAY_MAX).unwrap() {
        assert!(b.insert(v * 3));
    }
    assert!(matches!(b.containers.get(&0), Some(Container::Bits(_))));
    assert_eq!(b.len(), ARRAY_MAX + 1);
    let back = Bitmap::from_bytes(&b.to_bytes()).unwrap();
    assert_eq!(
        back.iter().collect::<Vec<_>>(),
        b.iter().collect::<Vec<_>>()
    );
    assert!(b.remove(0));
    assert!(matches!(b.containers.get(&0), Some(Container::Array(_))));
    assert!(!b.contains(0) && b.contains(3));
}

// §9.7A.1, CMP-9, Ek B 6126
#[test]
fn intersection_agrees_with_a_plain_set() {
    let mut seed = 7u64;
    for round in 0..20 {
        let size = if round % 2 == 0 { 300 } else { 9_000 };
        let a: Vec<u32> = (0..size).map(|_| lcg(&mut seed) % 200_000).collect();
        let b: Vec<u32> = (0..size).map(|_| lcg(&mut seed) % 200_000).collect();
        let (ba, bb): (Bitmap, Bitmap) = (a.iter().copied().collect(), b.iter().copied().collect());
        let sa: std::collections::BTreeSet<u32> = a.into_iter().collect();
        let sb: std::collections::BTreeSet<u32> = b.into_iter().collect();
        let both: Vec<u32> = sa.intersection(&sb).copied().collect();
        assert_eq!(ba.and(&bb).iter().collect::<Vec<_>>(), both);
        assert_eq!(ba.intersects(&bb), !both.is_empty());
        assert_eq!(ba.len(), sa.len());
        let back = Bitmap::from_bytes(&ba.to_bytes()).unwrap();
        assert_eq!(back, ba.iter().collect::<Bitmap>());
    }
}

// U48, §9.7A.1
#[test]
fn malformed_forms_are_refused() {
    let b: Bitmap = [5u32, 9, 70_000].into_iter().collect();
    let good = b.to_bytes();
    assert_eq!(
        Bitmap::from_bytes(&good[..good.len() - 1]),
        Err(BitmapError::Length)
    );
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(Bitmap::from_bytes(&trailing), Err(BitmapError::Length));
    let mut cookie = good.clone();
    cookie[0] = 0x3b;
    assert_eq!(Bitmap::from_bytes(&cookie), Err(BitmapError::Cookie));
    let mut keys = good.clone();
    keys[12] = 0;
    assert_eq!(Bitmap::from_bytes(&keys), Err(BitmapError::Container));
    let mut unsorted = good.clone();
    let at = good.len() - 6;
    unsorted[at] = 10;
    assert_eq!(Bitmap::from_bytes(&unsorted), Err(BitmapError::Container));
    let mut huge = Vec::new();
    huge.extend_from_slice(&COOKIE.to_le_bytes());
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(Bitmap::from_bytes(&huge).is_err());
}
