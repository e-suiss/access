extern crate std;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::sig::{P256_N, PureBackend};

const CT: &str = "application/test+cbor";

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn ed_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn p_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap()
}

fn keys() -> KeySet {
    let mut ks = KeySet::default();
    ks.insert(
        [1; 32],
        PublicKey::Ed25519(ed_key().verifying_key().to_bytes()),
    )
    .unwrap();
    let sec1 = p_key()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    ks.insert([2; 32], PublicKey::P256(sec1)).unwrap();
    ks.allowed.extend([Algorithm::Ed25519, Algorithm::Esp256]);
    ks
}

fn header(alg: Algorithm, kid: [u8; 32]) -> Vec<u8> {
    dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(alg.cose())),
            (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
            (Value::Unsigned(KID), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap()
}

fn message(prot: &[u8], payload: Option<&[u8]>, sig: &[u8]) -> Vec<u8> {
    let mut out = vec![0xd2, 0x84];
    let item = |v: Value| dcbor::encode(&v, Limits::CEILING).unwrap();
    out.extend(item(Value::Bytes(prot.to_vec())));
    out.extend(item(Value::Map(Vec::new())));
    match payload {
        Some(p) => out.extend(item(Value::Bytes(p.to_vec()))),
        None => out.push(0xf6),
    }
    out.extend(item(Value::Bytes(sig.to_vec())));
    out
}

fn ed_signed(prot: &[u8], payload: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    ed_key()
        .sign(&to_be_signed(prot, payload))
        .to_bytes()
        .to_vec()
}

fn p_signed(prot: &[u8], payload: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer as _;
    let sig: p256::ecdsa::Signature = p_key().sign(&to_be_signed(prot, payload));
    sig.normalize_s().to_bytes().to_vec()
}

fn high(low: &[u8]) -> Vec<u8> {
    let (r, s) = low.split_at(32);
    let mut out = [0_u8; 32];
    let mut borrow = false;
    for i in (0..32).rev() {
        let (d1, b1) = P256_N[i].overflowing_sub(s[i]);
        let (d2, b2) = d1.overflowing_sub(u8::from(borrow));
        out[i] = d2;
        borrow = b1 || b2;
    }
    [r, out.as_slice()].concat()
}

// OP-140 m.2: the view keeps the received bytes; a detached payload is `nil`
#[test]
fn parse_keeps_bytes_and_detached_payload() {
    let prot = header(Algorithm::Ed25519, [1; 32]);
    let attached = message(&prot, Some(b"p"), &[3; 64]);
    let view = parse_sign1(&attached).unwrap();
    assert_eq!(view.protected, prot);
    assert_eq!(view.payload.as_deref(), Some(b"p".as_slice()));
    assert_eq!(view.signature, vec![3; 64]);
    let detached = message(&prot, None, &[3; 64]);
    assert_eq!(parse_sign1(&detached).unwrap().payload, None);
    let mut trailing = attached.clone();
    trailing.push(0);
    assert!(matches!(
        parse_sign1(&trailing),
        Err(CoseError::Cbor(dcbor::DecodeError::TrailingBytes))
    ));
    assert!(matches!(
        parse_sign1(&attached[1..]),
        Err(CoseError::Cbor(dcbor::DecodeError::Tag))
    ));
}

// OP-140 m.2, RFC 9052 §2: a detached payload verifies only when given separately
#[test]
fn detached_payload_verifies_only_when_given() {
    let ks = keys();
    let prot = header(Algorithm::Ed25519, [1; 32]);
    let msg = message(&prot, None, &ed_signed(&prot, b"body"));
    let v = verify_sign1_detached(&PureBackend, &msg, b"body", &ks, CT).unwrap();
    assert_eq!(v.payload, b"body");
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::Payload)
    );
    assert!(verify_sign1_detached(&PureBackend, &msg, b"other", &ks, CT).is_err());
    let attached = message(&prot, Some(b"body"), &ed_signed(&prot, b"body"));
    assert_eq!(
        verify_sign1_detached(&PureBackend, &attached, b"body", &ks, CT),
        Err(CoseError::Payload)
    );
}

// CR-9, OP-140 m.2: high-S is refused for own artefacts and accepted from external signers
#[test]
fn high_s_depends_on_who_signed() {
    let ks = keys();
    let prot = header(Algorithm::Esp256, [2; 32]);
    let msg = message(&prot, Some(b"p"), &high(&p_signed(&prot, b"p")));
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::Signature(SignatureError::HighS))
    );
    assert!(verify_sign1_with(&PureBackend, &msg, None, &ks, CT, false).is_ok());
}

// CR-7: the algorithm comes from the caller's policy, never from the header
#[test]
fn algorithms_come_from_the_policy() {
    let mut ks = keys();
    let prot = header(Algorithm::Ed25519, [1; 32]);
    let msg = message(&prot, Some(b"p"), &ed_signed(&prot, b"p"));
    assert!(verify_sign1(&PureBackend, &msg, &ks, CT).is_ok());
    ks.allowed.remove(&Algorithm::Ed25519);
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::Algorithm)
    );
}

// OP-140 m.2: reason codes are stable strings
#[test]
fn codes_are_stable() {
    assert_eq!(CoseError::UnknownKid.code(), "cose-unknown-kid");
    assert_eq!(
        CoseError::Signature(SignatureError::HighS).code(),
        "signature-high-s"
    );
    assert_eq!(
        CoseError::Cbor(dcbor::DecodeError::KeyOrder).code(),
        "cbor-key-order"
    );
}

fn public_key(encoded: &[u8]) -> PublicKey {
    let Value::Map(entries) = dcbor::decode(encoded, Limits::CEILING).unwrap() else {
        panic!("key is not a map");
    };
    match entries.as_slice() {
        [(Value::Text(t), Value::Bytes(k))] if t == "ed25519" => {
            PublicKey::Ed25519(k.as_slice().try_into().unwrap())
        }
        [(Value::Text(t), Value::Bytes(k))] if t == "p256" => PublicKey::P256(k.clone()),
        _ => panic!("unexpected key"),
    }
}

fn name(e: CoseError) -> &'static str {
    match e {
        CoseError::Cbor(_) => "cbor",
        CoseError::Shape => "shape",
        CoseError::Header => "header",
        CoseError::Crit => "crit",
        CoseError::Unprotected => "unprotected",
        CoseError::Algorithm => "algorithm",
        CoseError::UnknownKid => "unknown-kid",
        CoseError::KeyType => "key-type",
        CoseError::ContentType => "content-type",
        CoseError::Signature(SignatureError::HighS) => "high-s",
        CoseError::Signature(_) => "signature",
        CoseError::Payload => "payload",
    }
}

#[derive(serde::Deserialize)]
struct Vectors {
    content_type: String,
    allowed: Vec<i64>,
    keys: std::collections::BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    sign1: String,
    kid: Option<String>,
    payload: Option<String>,
    error: Option<String>,
}

// CR-55 m.6, OP-140 m.3: the shared COSE vectors
#[test]
fn cose_vectors_match() {
    let v: Vectors = serde_json::from_str(include_str!("../../vectors/core/1/cose.json")).unwrap();
    let mut ks = KeySet::default();
    for (kid, key) in &v.keys {
        ks.insert(bytes(kid).try_into().unwrap(), public_key(&bytes(key)))
            .unwrap();
    }
    ks.allowed
        .extend(v.allowed.iter().map(|a| Algorithm::from_cose(*a).unwrap()));
    for c in &v.cases {
        match verify_sign1(&PureBackend, &bytes(&c.sign1), &ks, &v.content_type) {
            Ok(got) => {
                assert_eq!(
                    Some(bytes(c.kid.as_ref().unwrap())),
                    Some(got.kid.to_vec()),
                    "{}",
                    c.id
                );
                assert_eq!(bytes(c.payload.as_ref().unwrap()), got.payload, "{}", c.id);
            }
            Err(e) => assert_eq!(Some(name(e)), c.error.as_deref(), "{}", c.id),
        }
    }
}
