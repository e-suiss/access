#![allow(clippy::unwrap_used, reason = "test")]

use std::collections::BTreeMap;

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue, intent_digest};
use access_kernel::model::{ActionRef, ResourceRef, Window};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet, PublicKey, verify_sign1};
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::signer::{Signer, SoftSigner};

use super::*;

fn coordinates(key: &PublicKey) -> ([u8; 32], [u8; 32]) {
    let PublicKey::P256(sec1) = key else {
        panic!("p256")
    };
    let (x, y) = sec1[1..].split_at(32);
    (x.try_into().unwrap(), y.try_into().unwrap())
}

fn envelope() -> IntentEnvelope {
    IntentEnvelope {
        action: ActionRef {
            namespace: "idp.group".to_owned(),
            name: "create".to_owned(),
            major: 1,
            schema: Digest([7; 32]),
        },
        resources: vec![ResourceRef {
            namespace: "idp.realm".to_owned(),
            path: vec!["acme".to_owned(), "\"ops\"\n".to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::from([("name".to_owned(), ParamValue::Enum("ops".to_owned()))]),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 1_000,
            until: 2_000,
        },
    }
}

// OP-151 m.3 (e), X11
#[test]
fn a_webcrypto_style_signature_makes_a_verifiable_ais() {
    let (key, _) = SoftSigner::generate_p256().unwrap();
    let (x, y) = coordinates(&key.public_key());
    let kid = thumbprint_p256(&x, &y).unwrap();
    assert_eq!(kid, thumbprint(&key.public_key()).to_vec());
    let env = envelope();
    let intent = intent_digest(&env).unwrap();
    let basis_cbor = basis("public", &[1; 16]).unwrap();
    let payload = statement(
        &[3; 32],
        &[9; 16],
        &intent.0,
        "check",
        "access-console",
        &[],
        &basis_cbor,
        1_500,
        &[],
    )
    .unwrap();
    let prot = protected(-9, &kid).unwrap();
    let signature = key.sign(&to_be_signed(&prot, &payload).unwrap()).unwrap();
    let ais = sign1(&prot, &payload, &signature).unwrap();
    let mut keys = KeySet::default();
    keys.insert(kid.clone().try_into().unwrap(), key.public_key())
        .unwrap();
    keys.allowed.insert(Algorithm::Esp256);
    let verified = verify_sign1(&PureBackend, &ais, &keys, CONTENT_TYPE).unwrap();
    let s = Statement::from_bytes(&verified.payload).unwrap();
    assert_eq!(s.mode, Mode::Check);
    assert_eq!(s.intent, intent);
    let via_cbor = statement(
        &[3; 32],
        &[9; 16],
        &dcbor::encode(&intent.to_value(), Limits::CEILING).unwrap(),
        "check",
        "access-console",
        &[],
        &basis_cbor,
        1_500,
        &[],
    )
    .unwrap();
    assert_eq!(via_cbor, payload);
    let shown = describe_statement(&payload).unwrap();
    assert!(shown.contains("\"mode\":\"check\""));
    assert!(shown.contains("\"iat\":\"1500\""));
    assert!(shown.contains("\"capacity\":\"own\""));
    let i = describe_intent(&env.to_bytes().unwrap()).unwrap();
    assert!(i.contains("\"name\":\"create\""));
    assert!(i.contains("\\\"ops\\\"\\u000a"));
    assert!(i.contains(&format!("\"digest\":\"{}\"", b64url_encode(&intent.0))));
    assert!(i.contains("\"until\":\"2000\""));
}

// OP-151 m.3 (e)
#[test]
fn malformed_input_is_refused() {
    let basis_cbor = basis("anchor", &[1; 16]).unwrap();
    for (domain, nonce, mode) in [
        (&[3u8; 31][..], &[9u8; 16][..], "check"),
        (&[3; 32], &[9; 8], "check"),
        (&[3; 32], &[9; 16], "allow"),
    ] {
        assert!(statement(domain, nonce, &[4; 32], mode, "p", &[], &basis_cbor, 1, &[]).is_err());
    }
    assert!(
        statement(
            &[3; 32],
            &[9; 16],
            &[4; 32],
            "check",
            "",
            &[],
            &basis_cbor,
            1,
            &[]
        )
        .is_err()
    );
    assert!(
        statement(
            &[3; 32],
            &[9; 16],
            &[4; 32],
            "check",
            "p",
            &[1; 3],
            &basis_cbor,
            1,
            &[]
        )
        .is_err()
    );
    assert!(basis("holding", &[1; 16]).is_err());
    assert!(protected(-7, &[0; 32]).is_err());
    assert!(protected(-9, &[0; 31]).is_err());
    assert!(sign1(&[0xa0], b"x", &[0; 63]).is_err());
    assert!(cose_key_p256(&[0; 32], &[0; 32]).is_err());
    assert!(describe_statement(b"\x00").is_err());
    assert!(describe_intent(b"\x00").is_err());
}

// CR-10
#[test]
fn oversized_sig_structure_is_refused() {
    let prot = protected(-9, &[0; 32]).unwrap();
    let big = vec![0_u8; Limits::MAX_STRING + 1];
    assert_eq!(sig_structure(&prot, &big), Err("input"));
    assert_ne!(sig_structure(&prot, b"p").unwrap(), Vec::<u8>::new());
}
