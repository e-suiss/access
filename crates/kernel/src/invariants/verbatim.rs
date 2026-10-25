use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::binding;
use crate::codec::Canonical;
use crate::digest::{self, Context};
use crate::intent::{ContextRefs, IntentEnvelope, intent_digest};
use crate::json::b64url_encode;
use crate::model::{ActionRef, ResourceRef, Window};
use crate::verify::PureBackend;
use crate::verify::SignatureError;
use crate::verify::cose::{self, Algorithm, CoseError, KeySet, PublicKey};
use crate::verify::jws::{self, JwsError, Origin};
use crate::verify::sd_jwt::{self, Rules, SdJwtError};

const CT: &str = "application/access-receipt+cbor";
const TYP: &str = "access-receipt+jwt";

fn ed_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn sign(m: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    ed_key().sign(m).to_bytes().to_vec()
}

fn keys() -> KeySet {
    let mut k = KeySet::default();
    k.keys.insert(
        [1; 32],
        PublicKey::Ed25519(ed_key().verifying_key().to_bytes()),
    );
    k.allowed.insert(Algorithm::Ed25519);
    k
}

fn protected() -> Vec<u8> {
    dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(Algorithm::Ed25519.cose())),
            (Value::Unsigned(3), Value::text(CT)),
            (Value::Unsigned(4), Value::Bytes(vec![1; 32])),
        ]),
        Limits::CEILING,
    )
    .unwrap()
}

fn sign1(prot: &[u8], payload: &[u8], sig: &[u8]) -> Vec<u8> {
    let body = Value::Array(vec![
        Value::Bytes(prot.to_vec()),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_vec()),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

const NON_CANONICAL: [&[u8]; 4] = [
    &[0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02],
    &[0x18, 0x01],
    &[0x9f, 0x01, 0xff],
    &[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0],
];

// TI-11, §17.6.1 rule 2: the payload is returned as signed, never decoded and re-encoded
#[test]
fn cose_payload_is_returned_verbatim() {
    let prot = protected();
    for payload in NON_CANONICAL {
        assert!(dcbor::decode(payload, Limits::CEILING).is_err());
        let bytes = sign1(&prot, payload, &sign(&cose::to_be_signed(&prot, payload)));
        let v = cose::verify_sign1(&PureBackend, &bytes, &keys(), CT).unwrap();
        assert_eq!(v.payload, payload);

        let out = binding::verify_cose_sign1(
            &bytes,
            &dcbor::encode(&keys_value(), Limits::CEILING).unwrap(),
            CT,
        )
        .unwrap();
        let out = dcbor::decode(&out, Limits::CEILING).unwrap();
        assert_eq!(out.get("payload"), Some(&Value::Bytes(payload.to_vec())));
    }
}

fn keys_value() -> Value {
    Value::Map(vec![
        (
            Value::text("keys"),
            Value::Map(vec![(
                Value::Bytes(vec![1; 32]),
                Value::Map(vec![(
                    Value::text("ed25519"),
                    Value::Bytes(ed_key().verifying_key().to_bytes().to_vec()),
                )]),
            )]),
        ),
        (
            Value::text("allowed"),
            Value::Array(vec![Value::int(Algorithm::Ed25519.cose())]),
        ),
    ])
}

// TI-11: a signature over a re-encoded form of the payload does not verify the received bytes
#[test]
fn cose_signature_covers_the_received_bytes_only() {
    let prot = protected();
    let received = NON_CANONICAL[0];
    let canonical = [0xa2, 0x61, 0x61, 0x02, 0x61, 0x62, 0x01];
    let sig = sign(&cose::to_be_signed(&prot, &canonical));
    assert_eq!(
        cose::verify_sign1(&PureBackend, &sign1(&prot, received, &sig), &keys(), CT),
        Err(CoseError::Signature(SignatureError::Invalid))
    );
    assert!(cose::verify_sign1(&PureBackend, &sign1(&prot, &canonical, &sig), &keys(), CT).is_ok());
}

fn token(header: &str, payload: &str, signed_payload: &str) -> String {
    let h = b64url_encode(header.as_bytes());
    let signed = format!("{h}.{}", b64url_encode(signed_payload.as_bytes()));
    format!(
        "{h}.{}.{}",
        b64url_encode(payload.as_bytes()),
        b64url_encode(&sign(signed.as_bytes()))
    )
}

fn header() -> String {
    format!(
        r#"{{"alg":"Ed25519","kid":"{}","typ":"{TYP}"}}"#,
        b64url_encode(&[1; 32])
    )
}

// TI-11, OP-106 m.21: a JWS covers the JSON bytes exactly as received
#[test]
fn jws_payload_is_returned_verbatim() {
    let payload = "{ \"b\" : 1,\n  \"a\":\"\\u0041\" }";
    let t = token(&header(), payload, payload);
    let v = jws::verify_compact(&PureBackend, &t, &keys(), TYP, Origin::Native).unwrap();
    assert_eq!(v.payload, payload.as_bytes());

    let normalized = r#"{"a":"A","b":1}"#;
    let t = token(&header(), payload, normalized);
    assert!(matches!(
        jws::verify_compact(&PureBackend, &t, &keys(), TYP, Origin::Native),
        Err(JwsError::Signature(SignatureError::Invalid))
    ));
}

// TI-11: SD-JWT disclosure digests are computed by the verifier over the disclosure as presented
#[test]
fn sd_jwt_digests_are_recomputed_from_the_presented_disclosure() {
    let disclosure = b64url_encode(br#"["c2FsdA","email","a@example.com"]"#);
    let spaced = b64url_encode(br#"[ "c2FsdA", "email", "a@example.com" ]"#);
    let sd = b64url_encode(&Sha256::digest(disclosure.as_bytes()));
    let payload =
        format!(r#"{{"_sd":["{sd}"],"_sd_alg":"sha-256","exp":1,"iss":"https://issuer.example"}}"#);
    let jwt = token(&header(), &payload, &payload);
    let rules = Rules {
        typ: TYP,
        audience: "pep",
        nonce: "n",
        now: 0,
        skew_ms: 0,
    };
    let ok = sd_jwt::verify(
        &PureBackend,
        &format!("{jwt}~{disclosure}~"),
        &keys(),
        &rules,
        Origin::Native,
    )
    .unwrap();
    assert_eq!(
        ok.claims.get("email").and_then(|e| e.as_str()),
        Some("a@example.com")
    );
    assert_eq!(
        sd_jwt::verify(
            &PureBackend,
            &format!("{jwt}~{spaced}~"),
            &keys(),
            &rules,
            Origin::Native
        )
        .map(|_| ()),
        Err(SdJwtError::Unreferenced)
    );
}

fn envelope() -> IntentEnvelope {
    IntentEnvelope {
        action: ActionRef {
            namespace: String::from("pay"),
            name: String::from("refund"),
            major: 1,
            schema: crate::digest::Digest([9; 32]),
        },
        resources: vec![ResourceRef {
            namespace: String::from("shop"),
            path: vec![String::from("o1")],
            incarnation: 0,
        }],
        params: alloc::collections::BTreeMap::new(),
        opaque: alloc::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 100,
        },
    }
}

// TI-11, OP-106 m.21, m.22: the intent digest is computed from canonical CBOR only
#[test]
fn intent_digest_is_computed_from_canonical_cbor() {
    let e = envelope();
    let canonical = e.to_bytes().unwrap();
    let want = digest::digest(Context::Intent, &canonical);
    assert_eq!(intent_digest(&e).unwrap(), want);
    let mut h = Sha256::new();
    h.update(b"access/intent/v1\x00");
    h.update(&canonical);
    assert_eq!(want.0, <[u8; 32]>::from(h.finalize()));

    assert_eq!(
        binding::intent_digest(&canonical).unwrap(),
        dcbor::encode(&want.to_value(), Limits::CEILING).unwrap()
    );
    let mut reordered = dcbor::decode(&canonical, Limits::CEILING).unwrap();
    if let Value::Map(entries) = &mut reordered {
        entries.reverse();
    }
    let mut raw = vec![
        0xa0_u8
            | u8::try_from(match &reordered {
                Value::Map(m) => m.len(),
                _ => 0,
            })
            .unwrap(),
    ];
    if let Value::Map(entries) = &reordered {
        for (k, v) in entries {
            raw.extend(dcbor::encode(k, Limits::CEILING).unwrap());
            raw.extend(dcbor::encode(v, Limits::CEILING).unwrap());
        }
    }
    assert_ne!(raw, canonical);
    assert!(binding::intent_digest(&raw).is_err());
}
