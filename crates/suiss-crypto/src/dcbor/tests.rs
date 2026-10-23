use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn ok(h: &str, v: &Value) {
    let bytes = hex(h);
    assert_eq!(
        decode(&bytes, Limits::CEILING).as_ref(),
        Ok(v),
        "decode {h}"
    );
    assert_eq!(encode(v, Limits::CEILING).unwrap(), bytes, "encode {h}");
}

fn bad(h: &str, e: DecodeError) {
    assert_eq!(decode(&hex(h), Limits::CEILING), Err(e), "{h}");
}

// RFC 8949 Appendix A, items inside the profile.
#[test]
fn rfc8949_appendix_a() {
    ok("00", &Value::Unsigned(0));
    ok("17", &Value::Unsigned(23));
    ok("1818", &Value::Unsigned(24));
    ok("1903e8", &Value::Unsigned(1000));
    ok("1a000f4240", &Value::Unsigned(1_000_000));
    ok("1b000000e8d4a51000", &Value::Unsigned(1_000_000_000_000));
    ok("1bffffffffffffffff", &Value::Unsigned(u64::MAX));
    ok("20", &Value::int(-1));
    ok("3863", &Value::int(-100));
    ok("3bffffffffffffffff", &Value::Negative(u64::MAX));
    ok("f4", &Value::Bool(false));
    ok("f5", &Value::Bool(true));
    ok("40", &Value::Bytes(vec![]));
    ok("4401020304", &Value::Bytes(vec![1, 2, 3, 4]));
    ok("60", &Value::text(""));
    ok("6449455446", &Value::text("IETF"));
    ok("62c3bc", &Value::text("\u{fc}"));
    ok("80", &Value::Array(vec![]));
    ok(
        "8301820203820405",
        &Value::Array(vec![
            Value::Unsigned(1),
            Value::Array(vec![Value::Unsigned(2), Value::Unsigned(3)]),
            Value::Array(vec![Value::Unsigned(4), Value::Unsigned(5)]),
        ]),
    );
    ok("a0", &Value::Map(vec![]));
    ok(
        "a201020304",
        &Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::Unsigned(3), Value::Unsigned(4)),
        ]),
    );
}

#[test]
fn integer_conversions() {
    for n in [0, 1, 23, 24, -1, -24, -25, i64::MAX, i64::MIN] {
        assert_eq!(Value::int(n).as_i64(), Some(n), "{n}");
    }
    assert_eq!(Value::Unsigned(u64::MAX).as_i64(), None);
    assert_eq!(Value::Negative(u64::MAX).as_i64(), None);
}

// CR-10, OP-106 m.1–m.3
#[test]
fn non_canonical_and_out_of_profile_input_is_rejected() {
    bad("1817", DecodeError::NonShortest);
    bad("190017", DecodeError::NonShortest);
    bad("1900ff", DecodeError::NonShortest);
    bad("1a0000ffff", DecodeError::NonShortest);
    bad("1b00000000ffffffff", DecodeError::NonShortest);
    bad("5800", DecodeError::NonShortest);
    bad("5f42010243030405ff", DecodeError::Indefinite);
    bad("9fff", DecodeError::Indefinite);
    bad("bfff", DecodeError::Indefinite);
    bad("1c", DecodeError::Reserved);
    bad("f90000", DecodeError::Float);
    bad("fa47c35000", DecodeError::Float);
    bad("fb3ff199999999999a", DecodeError::Float);
    bad("f6", DecodeError::Simple);
    bad("f7", DecodeError::Simple);
    bad("f0", DecodeError::Simple);
    bad("f820", DecodeError::Simple);
    bad("c11a514b67b0", DecodeError::Tag);
    bad("d2a0", DecodeError::Tag);
    bad("62c328", DecodeError::Utf8);
    bad("a203040102", DecodeError::KeyOrder);
    bad("a201020103", DecodeError::DuplicateKey);
    bad("a2616201616101", DecodeError::KeyOrder);
    bad("a26161016162", DecodeError::Truncated);
    bad("0000", DecodeError::TrailingBytes);
    bad("", DecodeError::Truncated);
    bad("19", DecodeError::Truncated);
    bad("4301", DecodeError::Truncated);
}

// RFC 8949 §4.2.1: shorter encoded keys sort first, then bytewise.
#[test]
fn map_keys_sort_by_encoded_bytes() {
    let v = Value::Map(vec![
        (Value::text("aa"), Value::Unsigned(1)),
        (Value::text("b"), Value::Unsigned(2)),
        (Value::Unsigned(10), Value::Unsigned(3)),
        (Value::int(-1), Value::Unsigned(4)),
    ]);
    let bytes = encode(&v, Limits::CEILING).unwrap();
    assert_eq!(bytes, hex("a40a03200461620262616101"));
    assert!(decode(&bytes, Limits::CEILING).is_ok());
}

#[test]
fn encoder_rejects_duplicate_keys() {
    let v = Value::Map(vec![
        (Value::text("a"), Value::Unsigned(1)),
        (Value::text("a"), Value::Unsigned(2)),
    ]);
    assert_eq!(encode(&v, Limits::CEILING), Err(EncodeError::DuplicateKey));
}

// §14.6, OP-106 m.5
#[test]
fn limits_are_enforced_and_cannot_be_raised() {
    let mut nested = Value::Array(vec![]);
    for _ in 0..Limits::MAX_DEPTH {
        nested = Value::Array(vec![nested]);
    }
    let bytes = encode(&Value::Array(vec![]), Limits::CEILING).unwrap();
    assert!(decode(&bytes, Limits::CEILING).is_ok());
    assert_eq!(encode(&nested, Limits::CEILING), Err(EncodeError::Limits));
    let deep = [vec![0x81_u8; Limits::MAX_DEPTH + 1], vec![0x80]].concat();
    assert_eq!(decode(&deep, Limits::CEILING), Err(DecodeError::Depth));
    let ok_depth = [vec![0x81_u8; Limits::MAX_DEPTH - 1], vec![0x80]].concat();
    assert!(decode(&ok_depth, Limits::CEILING).is_ok());

    assert_eq!(
        decode(&hex("990101"), Limits::CEILING),
        Err(DecodeError::Items)
    );
    assert_eq!(
        decode(&hex("5a00010001"), Limits::CEILING),
        Err(DecodeError::StringLength)
    );

    let tight = Limits::tightened(1, 2, 3).unwrap();
    assert_eq!(decode(&hex("8180"), tight), Err(DecodeError::Depth));
    assert_eq!(decode(&hex("83010203"), tight), Err(DecodeError::Items));
    assert_eq!(
        decode(&hex("4401020304"), tight),
        Err(DecodeError::StringLength)
    );
    assert_eq!(Limits::tightened(17, 1, 1), None);
    assert_eq!(Limits::tightened(1, 257, 1), None);
    assert_eq!(Limits::tightened(1, 1, 64 * 1024 + 1), None);
}

#[test]
fn cose_sign1_tag_only_on_the_outside() {
    let inner = hex("8443a10126a0f640");
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(&inner);
    assert_eq!(
        decode_tagged(&tagged, COSE_SIGN1_TAG, Limits::CEILING),
        Err(DecodeError::Simple)
    );
    let inner = hex("8443a10126a04040");
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(&inner);
    assert!(decode_tagged(&tagged, COSE_SIGN1_TAG, Limits::CEILING).is_ok());
    assert_eq!(
        decode_tagged(&inner, COSE_SIGN1_TAG, Limits::CEILING),
        Err(DecodeError::Tag)
    );
    assert_eq!(
        decode_tagged(&tagged, 1, Limits::CEILING),
        Err(DecodeError::Tag)
    );
    let nested = [vec![0xd2, 0xd2], inner].concat();
    assert_eq!(
        decode_tagged(&nested, COSE_SIGN1_TAG, Limits::CEILING),
        Err(DecodeError::Tag)
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    fn value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            any::<u64>().prop_map(Value::Unsigned),
            any::<u64>().prop_map(Value::Negative),
            any::<bool>().prop_map(Value::Bool),
            proptest::collection::vec(any::<u8>(), 0..16).prop_map(Value::Bytes),
            "[a-z]{0,8}".prop_map(|s| Value::text(&s)),
        ];
        leaf.prop_recursive(4, 32, 6, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                proptest::collection::btree_map("[a-z]{1,4}", inner, 0..6).prop_map(|m| {
                    Value::Map(m.into_iter().map(|(k, v)| (Value::text(&k), v)).collect())
                }),
            ]
        })
    }

    proptest! {
        #[test]
        fn decode_of_encode_is_identity_up_to_key_order(v in value()) {
            let bytes = encode(&v, Limits::CEILING).unwrap();
            let back = decode(&bytes, Limits::CEILING).unwrap();
            prop_assert_eq!(encode(&back, Limits::CEILING).unwrap(), bytes);
        }

        #[test]
        fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok(v) = decode(&bytes, Limits::CEILING) {
                prop_assert_eq!(encode(&v, Limits::CEILING).unwrap(), bytes);
            }
        }
    }
}
