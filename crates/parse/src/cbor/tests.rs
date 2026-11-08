use proptest::prelude::*;

use super::*;

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn dec(h: &str) -> Result<Item<'static>, CborError> {
    let bytes: &'static [u8] = Box::leak(hex(h).into_boxed_slice());
    decode(bytes, Limits::CEILING)
}

// CR-10
#[test]
fn decodes_cose_key_shapes() {
    let item = dec("a501020326200121582001010101010101010101010101010101010101010101010101010101010101012258200202020202020202020202020202020202020202020202020202020202020202").unwrap();
    assert_eq!(item.get_int(1).and_then(Item::as_i64), Some(2));
    assert_eq!(item.get_int(3).and_then(Item::as_i64), Some(-7));
    assert_eq!(item.get_int(-1).and_then(Item::as_i64), Some(1));
    assert_eq!(
        item.get_int(-2).and_then(Item::as_bytes),
        Some(&[1_u8; 32][..])
    );
    assert_eq!(dec("f5"), Ok(Item::Bool(true)));
    assert_eq!(dec("6449455446"), Ok(Item::Text("IETF")));
    assert_eq!(dec("3bffffffffffffffff").unwrap().as_i64(), None);
}

// CR-10
#[test]
fn accepts_unsorted_keys_and_long_forms() {
    assert!(dec("a2036161016162").is_ok());
    assert_eq!(dec("1801"), Ok(Item::Unsigned(1)));
}

// CR-10
#[test]
fn rejects_out_of_profile_input() {
    assert_eq!(dec("a2016101180162"), Err(CborError::DuplicateKey));
    assert_eq!(dec("9fff"), Err(CborError::Indefinite));
    assert_eq!(dec("5f40ff"), Err(CborError::Indefinite));
    assert_eq!(dec("f97e00"), Err(CborError::Float));
    assert_eq!(dec("f6"), Err(CborError::Simple));
    assert_eq!(dec("f7"), Err(CborError::Simple));
    assert_eq!(dec("c11a514b67b0"), Err(CborError::Tag));
    assert_eq!(dec("1c"), Err(CborError::Reserved));
    assert_eq!(dec("62c3"), Err(CborError::Truncated));
    assert_eq!(dec("62c328"), Err(CborError::Utf8));
    assert_eq!(dec("0000"), Err(CborError::TrailingBytes));
    assert_eq!(dec("5bffffffffffffffff"), Err(CborError::Truncated));
    assert_eq!(dec("9b0000000100000000"), Err(CborError::Items));
}

// CR-10 m.3, m.5
#[test]
fn depth_items_and_size_limits() {
    let deep = |n: usize| {
        let mut v = vec![0x81_u8; n];
        v.push(0x00);
        v
    };
    assert!(decode(&deep(16), Limits::CEILING).is_ok());
    assert_eq!(decode(&deep(17), Limits::CEILING), Err(CborError::Depth));
    let mut many = vec![0x99, 0x01, 0x01];
    many.extend(std::iter::repeat_n(0x00, 257));
    assert_eq!(decode(&many, Limits::CEILING), Err(CborError::Items));
    let big = vec![0x00; MAX_INPUT + 1];
    assert_eq!(decode(&big, Limits::CEILING), Err(CborError::InputTooLarge));
    let five = {
        let mut v = vec![0x86];
        for _ in 0..6 {
            v.extend([0x98, 0xc8]);
            v.extend(std::iter::repeat_n(0x00, 200));
        }
        v
    };
    assert_eq!(decode(&five, Limits::CEILING), Err(CborError::TotalItems));
    let tight = Limits::tightened(64, 2, 4, 16).unwrap();
    assert_eq!(decode(&deep(3), tight), Err(CborError::Depth));
    assert!(Limits::tightened(MAX_INPUT + 1, 1, 1, 1).is_none());
    assert!(Limits::tightened(1, 17, 1, 1).is_none());
}

#[test]
fn prefix_reports_consumed_length() {
    let bytes = hex("a10102ff00");
    let (item, used) = decode_prefix(&bytes, Limits::CEILING).unwrap();
    assert_eq!(used, 3);
    assert_eq!(item.get_int(1), Some(&Item::Unsigned(2)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    // CR-10 m.4
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok((_, used)) = decode_prefix(&bytes, Limits::CEILING) {
            prop_assert!(used <= bytes.len());
        }
    }

    // CR-10 m.4
    #[test]
    fn container_heavy_input_never_panics(
        bytes in proptest::collection::vec(prop_oneof![Just(0x81_u8), Just(0xa1), Just(0x9f), Just(0x00), Just(0x41), any::<u8>()], 0..512)
    ) {
        let _ = decode(&bytes, Limits::CEILING);
    }
}
