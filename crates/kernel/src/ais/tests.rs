use alloc::vec;

use ed25519_dalek::Signer as _;

use super::*;
use crate::model::Id;
use crate::verify::cose::{ALG, CONTENT_TYPE as CT_LABEL, KID, to_be_signed};

fn signing() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[11; 32])
}

fn key() -> PublicKey {
    PublicKey::Ed25519(signing().verifying_key().to_bytes())
}

fn statement() -> Statement {
    Statement {
        domain: Digest([1; 32]),
        nonce: vec![2; 16],
        intent: Digest([3; 32]),
        mode: Mode::Commit,
        pep: String::from("pep.example"),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Public(Id([4; 16])),
        iat: 1_000,
        exercise: None,
    }
}

pub(crate) fn sign(s: &Statement, with: &ed25519_dalek::SigningKey) -> Vec<u8> {
    let kid = thumbprint(&PublicKey::Ed25519(with.verifying_key().to_bytes()));
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(CT_LABEL), Value::text(CONTENT_TYPE)),
            (Value::Unsigned(KID), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let payload = s.to_bytes().unwrap();
    let sig = with.sign(&to_be_signed(&prot, &payload)).to_bytes();
    let body = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(sig.to_vec()),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    [vec![0xd2], body].concat()
}

fn expected(s: &Statement) -> Expected<'_> {
    Expected {
        domain: &s.domain,
        nonce: &s.nonce,
        intent: &s.intent,
        mode: s.mode,
        pep: &s.pep,
        capacity: s.capacity,
        basis: &s.basis,
        exercise: s.exercise.as_ref(),
    }
}

// PI-7, SI-1, OP-141 m.7: the actor's key signs exactly the request
#[test]
fn a_statement_binds_the_request() {
    let s = statement();
    let signed = sign(&s, &signing());
    assert_eq!(verify(&signed, &key(), &expected(&s), 1_000).unwrap(), s);
    let other = Digest([9; 32]);
    let mut e = expected(&s);
    e.intent = &other;
    assert_eq!(
        verify(&signed, &key(), &e, 1_000),
        Err(AisError::Mismatch("intent"))
    );
    let mut e = expected(&s);
    e.pep = "other.example";
    assert_eq!(
        verify(&signed, &key(), &e, 1_000),
        Err(AisError::Mismatch("pep"))
    );
    let mut e = expected(&s);
    e.mode = Mode::Check;
    assert_eq!(
        verify(&signed, &key(), &e, 1_000),
        Err(AisError::Mismatch("mode"))
    );
}

// SI-1, E17: only the actor Instance's current key makes the statement its own
#[test]
fn another_key_is_refused() {
    let s = statement();
    let signed = sign(&s, &ed25519_dalek::SigningKey::from_bytes(&[12; 32]));
    assert!(matches!(
        verify(&signed, &key(), &expected(&s), 1_000),
        Err(AisError::Signature(_))
    ));
}

// CR-55 m.9: a statement from the future beyond the skew is refused
#[test]
fn future_statements_are_refused() {
    let mut s = statement();
    s.iat = 100_000;
    let signed = sign(&s, &signing());
    assert_eq!(
        verify(&signed, &key(), &expected(&s), 39_999),
        Err(AisError::Future)
    );
    assert!(verify(&signed, &key(), &expected(&s), 40_000).is_ok());
}

// OP-141 m.7: the payload round-trips and short nonces are refused
#[test]
fn payload_shape() {
    let s = statement();
    assert_eq!(Statement::from_value(&s.to_value()).unwrap(), s);
    let mut short = s.clone();
    short.nonce = vec![1; 8];
    assert_eq!(
        Statement::from_value(&short.to_value()),
        Err(ModelError::Range)
    );
}

// L2-AIS-*: statement vectors, byte for byte
#[test]
fn ais_vectors_match() {
    use crate::vector_rules::{field, golden, hex};
    use alloc::format;
    let s = statement();
    let good = sign(&s, &signing());
    let mut future = statement();
    future.iat = 100_000;
    let mut short = statement();
    short.nonce = vec![1; 8];
    let cases: Vec<(&str, &[&str], Vec<u8>, Statement, u64)> = vec![
        (
            "valid",
            &["L2-AIS-1", "L2-AIS-2", "L2-AIS-3"],
            good.clone(),
            s.clone(),
            1_000,
        ),
        (
            "intent-differs",
            &["L2-AIS-3"],
            good.clone(),
            Statement {
                intent: Digest([9; 32]),
                ..s.clone()
            },
            1_000,
        ),
        (
            "pep-differs",
            &["L2-AIS-3"],
            good.clone(),
            Statement {
                pep: String::from("other.example"),
                ..s.clone()
            },
            1_000,
        ),
        (
            "mode-differs",
            &["L2-AIS-3"],
            good.clone(),
            Statement {
                mode: Mode::Check,
                ..s.clone()
            },
            1_000,
        ),
        (
            "nonce-differs",
            &["L2-AIS-3"],
            good.clone(),
            Statement {
                nonce: vec![3; 16],
                ..s.clone()
            },
            1_000,
        ),
        (
            "basis-differs",
            &["L2-AIS-3"],
            good.clone(),
            Statement {
                basis: ExerciseBasis::Anchor(Id([4; 16])),
                ..s.clone()
            },
            1_000,
        ),
        (
            "other-key",
            &["L2-AIS-2"],
            sign(&s, &ed25519_dalek::SigningKey::from_bytes(&[12; 32])),
            s.clone(),
            1_000,
        ),
        (
            "future",
            &["L2-AIS-4"],
            sign(&future, &signing()),
            future.clone(),
            39_999,
        ),
        (
            "future-within-skew",
            &["L2-AIS-4"],
            sign(&future, &signing()),
            future.clone(),
            40_000,
        ),
        (
            "nonce-too-short",
            &["L2-AIS-1"],
            sign(&short, &signing()),
            short.clone(),
            1_000,
        ),
    ];
    let mut rows = Vec::new();
    for (id, rules, sign1, exp, now) in &cases {
        let expect = match verify(sign1, &key(), &expected(exp), *now) {
            Ok(_) => String::from("\"valid\": true"),
            Err(AisError::Mismatch(f)) => {
                format!("\"error\": \"ais-mismatch\", \"field\": \"{f}\"")
            }
            Err(e) => format!("\"error\": \"{}\"", e.code()),
        };
        let request = exp.to_bytes().unwrap();
        rows.push(format!(
            "  {{\"id\": \"{id}\", {}, \"sign1\": \"{}\", \"request\": \"{}\", \"now\": {now}, {expect}}}",
            field(rules),
            hex(sign1),
            hex(&request)
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-141\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"ais.verify\",\n {},\n \"key\": \"{}\",\n \"cases\": [\n{}\n ]\n}}\n",
        field(&["L2-AIS-1"]),
        hex(&key().to_bytes().unwrap()),
        rows.join(",\n")
    );
    golden(
        "ais.json",
        include_str!("../../../../conformance/vectors/core/1/ais.json"),
        &json,
    );
}
