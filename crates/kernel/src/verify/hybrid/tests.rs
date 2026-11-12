use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::verify::cose::{ALG, Algorithm, CONTENT_TYPE, KID};

fn sign1(alg: Algorithm, sig: u8) -> Vec<u8> {
    let protected = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(alg.cose())),
            (
                Value::Unsigned(CONTENT_TYPE),
                Value::text("application/access-receipt+cbor"),
            ),
            (Value::Unsigned(KID), Value::Bytes(vec![3; 32])),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let body = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(vec![]),
        Value::Bytes(b"receipt".to_vec()),
        Value::Bytes(vec![sig; 8]),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

// OP-159 m.15 (b), CR-42 m.4, SAI-44
#[test]
fn the_carrier_round_trips_classical_first() {
    let (c, p) = (sign1(Algorithm::Ed25519, 1), sign1(Algorithm::MlDsa65, 2));
    let carrier = encode_carrier(&c, &p).unwrap();
    assert_eq!(decode_carrier(&carrier), Ok((c.clone(), p.clone())));
    assert_eq!(encode_carrier(&p, &c), Err(HybridError::Carrier));
    assert_eq!(
        encode_carrier(&c, &sign1(Algorithm::Esp256, 2)),
        Err(HybridError::Carrier)
    );
    let swapped = dcbor::encode(
        &Value::Array(vec![Value::Bytes(p.clone()), Value::Bytes(c.clone())]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(decode_carrier(&swapped), Err(HybridError::Carrier));
    let three = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(c.clone()),
            Value::Bytes(p.clone()),
            Value::Bytes(p.clone()),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(decode_carrier(&three), Err(HybridError::Carrier));
    assert_eq!(decode_carrier(&c), Err(HybridError::Carrier));
    assert_eq!(HybridError::Carrier.code(), "hybrid-carrier");
}
