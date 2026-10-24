use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::verify::{P256_N, PureBackend};

fn header(entries: Vec<(Value, Value)>) -> Vec<u8> {
    dcbor::encode(&Value::Map(entries), Limits::CEILING).unwrap()
}

fn std_header(alg: Algorithm, kid: [u8; 32]) -> Vec<u8> {
    header(vec![
        (Value::Unsigned(ALG), Value::int(alg.cose())),
        (Value::Unsigned(KID), Value::Bytes(kid.to_vec())),
        (
            Value::Unsigned(CONTENT_TYPE),
            Value::text("application/access-receipt+cbor"),
        ),
    ])
}

fn sign1(prot: &[u8], unprot: Value, payload: &[u8], sig: &[u8]) -> Vec<u8> {
    let body = Value::Array(vec![
        Value::Bytes(prot.to_vec()),
        unprot,
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_vec()),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

const CT: &str = "application/access-receipt+cbor";

fn ed_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn p_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap()
}

fn keys() -> KeySet {
    let mut k = KeySet::default();
    k.keys.insert(
        [1; 32],
        PublicKey::Ed25519(ed_key().verifying_key().to_bytes()),
    );
    k.keys.insert(
        [2; 32],
        PublicKey::P256(
            p_key()
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        ),
    );
    k.allowed.extend([Algorithm::Ed25519, Algorithm::Esp256]);
    k
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

fn empty() -> Value {
    Value::Map(vec![])
}

// CR-55 m.6
#[test]
fn valid_ed25519_and_esp256() {
    let prot = std_header(Algorithm::Ed25519, [1; 32]);
    let msg = sign1(&prot, empty(), b"payload", &ed_signed(&prot, b"payload"));
    let v = verify_sign1(&PureBackend, &msg, &keys(), CT).unwrap();
    assert_eq!(
        (v.algorithm, v.kid, v.payload.as_slice()),
        (Algorithm::Ed25519, [1; 32], &b"payload"[..])
    );

    let prot = std_header(Algorithm::Esp256, [2; 32]);
    let msg = sign1(&prot, empty(), b"p", &p_signed(&prot, b"p"));
    assert!(verify_sign1(&PureBackend, &msg, &keys(), CT).is_ok());
}

// CR-55 m.6, CR-7, CR-56 rows 3, 4, 8, 9
#[test]
fn profile_violations_are_rejected() {
    let ks = keys();
    let prot = std_header(Algorithm::Ed25519, [1; 32]);
    let sig = ed_signed(&prot, b"payload");
    let good = sign1(&prot, empty(), b"payload", &sig);

    assert!(matches!(
        verify_sign1(&PureBackend, &good[1..], &ks, CT),
        Err(CoseError::Cbor(_))
    ));
    assert_eq!(
        verify_sign1(&PureBackend, &good, &ks, "application/other"),
        Err(CoseError::ContentType)
    );
    let tampered = sign1(&prot, empty(), b"payloae", &sig);
    assert_eq!(
        verify_sign1(&PureBackend, &tampered, &ks, CT),
        Err(CoseError::Signature(SignatureError::Invalid))
    );

    let unprot = Value::Map(vec![(Value::Unsigned(KID), Value::Bytes(vec![1; 32]))]);
    assert_eq!(
        verify_sign1(
            &PureBackend,
            &sign1(&prot, unprot, b"payload", &sig),
            &ks,
            CT
        ),
        Err(CoseError::Unprotected)
    );

    let mut only_ed = ks.clone();
    only_ed.allowed.remove(&Algorithm::Esp256);
    let p_prot = std_header(Algorithm::Esp256, [2; 32]);
    let p_msg = sign1(&p_prot, empty(), b"p", &p_signed(&p_prot, b"p"));
    assert_eq!(
        verify_sign1(&PureBackend, &p_msg, &only_ed, CT),
        Err(CoseError::Algorithm)
    );

    let swapped = std_header(Algorithm::Ed25519, [2; 32]);
    let msg = sign1(&swapped, empty(), b"x", &ed_signed(&swapped, b"x"));
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::KeyType)
    );

    let unknown = std_header(Algorithm::Ed25519, [3; 32]);
    let msg = sign1(&unknown, empty(), b"x", &ed_signed(&unknown, b"x"));
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::UnknownKid)
    );

    let eddsa = header(vec![
        (Value::Unsigned(ALG), Value::int(-8)),
        (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
        (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
    ]);
    let msg = sign1(&eddsa, empty(), b"x", &ed_signed(&eddsa, b"x"));
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::Algorithm)
    );

    let with = |extra: (Value, Value)| {
        let mut e = vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
            (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
        ];
        e.push(extra);
        let h = header(e);
        sign1(&h, empty(), b"x", &ed_signed(&h, b"x"))
    };
    assert_eq!(
        verify_sign1(
            &PureBackend,
            &with((
                Value::Unsigned(CRIT),
                Value::Array(vec![Value::Unsigned(99)])
            )),
            &ks,
            CT
        ),
        Err(CoseError::Crit)
    );
    assert_eq!(
        verify_sign1(
            &PureBackend,
            &with((Value::Unsigned(33), Value::Bytes(vec![]))),
            &ks,
            CT
        ),
        Err(CoseError::Header)
    );
    let missing_ct = header(vec![
        (Value::Unsigned(ALG), Value::int(-19)),
        (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
    ]);
    let msg = sign1(&missing_ct, empty(), b"x", &ed_signed(&missing_ct, b"x"));
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::Header)
    );
}

fn sub_from_n(s: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; 32];
    let mut borrow = false;
    for i in (0..32).rev() {
        let (d1, b1) = P256_N[i].overflowing_sub(s[i]);
        let (d2, b2) = d1.overflowing_sub(u8::from(borrow));
        out[i] = d2;
        borrow = b1 || b2;
    }
    out
}

// CR-9, CR-56 row 13
#[test]
fn high_s_is_rejected_for_native_artefacts() {
    let prot = std_header(Algorithm::Esp256, [2; 32]);
    let low = p_signed(&prot, b"p");
    let high = [low[..32].to_vec(), sub_from_n(&low[32..])].concat();
    assert!(
        p256(
            &PureBackend,
            &keys().keys[&[2; 32]].p256_bytes(),
            &to_be_signed(&prot, b"p"),
            &high,
            false
        )
        .is_ok()
    );
    let msg = sign1(&prot, empty(), b"p", &high);
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &keys(), CT),
        Err(CoseError::Signature(SignatureError::HighS))
    );
}

impl PublicKey {
    fn p256_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(b) => b.clone(),
            Self::Ed25519(_) | Self::MlDsa(..) => Vec::new(),
        }
    }
}

// CR-55 m.1, Ek B: AKP is modelled from day one and off by default
#[test]
fn ml_dsa_is_modelled_but_off() {
    let mut ks = keys();
    assert_eq!(
        ks.insert([5; 32], PublicKey::MlDsa(Algorithm::MlDsa65, vec![0; 1952])),
        Ok(())
    );
    assert_eq!(
        ks.insert([6; 32], PublicKey::MlDsa(Algorithm::MlDsa65, vec![0; 1951])),
        Err(SignatureError::Length)
    );
    ks.allowed.insert(Algorithm::MlDsa65);
    let prot = std_header(Algorithm::MlDsa65, [5; 32]);
    let msg = sign1(&prot, empty(), b"p", &[0; 3309]);
    assert_eq!(
        verify_sign1(&PureBackend, &msg, &ks, CT),
        Err(CoseError::Algorithm)
    );
    assert!(!Algorithm::MlDsa44.enabled() && Algorithm::Ed25519.enabled());
}

fn cose_cases() -> Vec<(&'static str, Vec<u8>)> {
    let ed = std_header(Algorithm::Ed25519, [1; 32]);
    let es = std_header(Algorithm::Esp256, [2; 32]);
    let good = sign1(&ed, empty(), b"payload", &ed_signed(&ed, b"payload"));
    let low = p_signed(&es, b"p");
    let high = [low[..32].to_vec(), sub_from_n(&low[32..])].concat();
    let with = |entries: Vec<(Value, Value)>| {
        let h = header(entries);
        sign1(&h, empty(), b"x", &ed_signed(&h, b"x"))
    };
    let base = || {
        vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
            (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
        ]
    };
    let mut crit = base();
    crit.push((
        Value::Unsigned(CRIT),
        Value::Array(vec![Value::Unsigned(99)]),
    ));
    let mut extra = base();
    extra.push((Value::Unsigned(33), Value::Bytes(vec![])));
    let swapped = std_header(Algorithm::Ed25519, [2; 32]);
    let unknown = std_header(Algorithm::Ed25519, [3; 32]);
    let es256 = std_header(Algorithm::Es256, [2; 32]);
    let ml = std_header(Algorithm::MlDsa65, [1; 32]);
    vec![
        ("valid-ed25519", good.clone()),
        ("valid-esp256", sign1(&es, empty(), b"p", &low)),
        ("untagged", good[1..].to_vec()),
        (
            "payload-tampered",
            sign1(&ed, empty(), b"payloae", &ed_signed(&ed, b"payload")),
        ),
        ("esp256-high-s", sign1(&es, empty(), b"p", &high)),
        (
            "kid-in-unprotected",
            sign1(
                &ed,
                Value::Map(vec![(Value::Unsigned(KID), Value::Bytes(vec![1; 32]))]),
                b"payload",
                &ed_signed(&ed, b"payload"),
            ),
        ),
        (
            "key-type-mismatch",
            sign1(&swapped, empty(), b"x", &ed_signed(&swapped, b"x")),
        ),
        (
            "kid-unknown",
            sign1(&unknown, empty(), b"x", &ed_signed(&unknown, b"x")),
        ),
        (
            "alg-eddsa",
            with(vec![
                (Value::Unsigned(ALG), Value::int(-8)),
                (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
                (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
            ]),
        ),
        (
            "alg-es256-not-allowed",
            sign1(&es256, empty(), b"p", &p_signed(&es256, b"p")),
        ),
        ("alg-ml-dsa-65-off", sign1(&ml, empty(), b"p", &[0; 3309])),
        ("crit", with(crit)),
        ("header-unknown", with(extra)),
        (
            "content-type-missing",
            with(vec![
                (Value::Unsigned(ALG), Value::int(-19)),
                (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
            ]),
        ),
        (
            "content-type-other",
            with(vec![
                (Value::Unsigned(ALG), Value::int(-19)),
                (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
                (
                    Value::Unsigned(CONTENT_TYPE),
                    Value::text("application/other"),
                ),
            ]),
        ),
    ]
    .into_iter()
    .chain(two_fault_cases())
    .collect()
}

// OP-117 m.14: the first failing step wins
fn two_fault_cases() -> Vec<(&'static str, Vec<u8>)> {
    let base = || {
        vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(KID), Value::Bytes(vec![1; 32])),
            (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
        ]
    };
    let with = |entries: Vec<(Value, Value)>| {
        let h = header(entries);
        sign1(&h, empty(), b"x", &ed_signed(&h, b"x"))
    };
    vec![
        ("two-faults-unprotected-and-unknown-label", {
            let mut e = base();
            e.push((Value::Unsigned(33), Value::Bytes(vec![])));
            let h = header(e);
            sign1(
                &h,
                Value::Map(vec![(Value::Unsigned(KID), Value::Bytes(vec![1; 32]))]),
                b"x",
                &ed_signed(&h, b"x"),
            )
        }),
        (
            "two-faults-content-type-and-unknown-kid",
            with(vec![
                (Value::Unsigned(ALG), Value::int(-19)),
                (Value::Unsigned(KID), Value::Bytes(vec![3; 32])),
                (
                    Value::Unsigned(CONTENT_TYPE),
                    Value::text("application/other"),
                ),
            ]),
        ),
    ]
}

fn cose_error(e: CoseError) -> &'static str {
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
    }
}

// CR-55 m.6, OP-106 m.24, §17.6.1: COSE golden vectors, byte for byte
#[test]
fn cose_vectors_match() {
    extern crate std;
    use crate::codec::Canonical;
    use alloc::string::String;
    use core::fmt::Write as _;
    let hex = |b: &[u8]| {
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    };
    let ks = keys();
    let mut json = String::from(
        "{\n \"rule\": \"CR-55\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"verify.cose_sign1\",\n",
    );
    let _ = writeln!(json, " \"content_type\": \"{CT}\",");
    let allowed = ks
        .allowed
        .iter()
        .map(|a| alloc::format!("{}", a.cose()))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(json, " \"allowed\": [{allowed}],");
    let keys = ks
        .keys
        .iter()
        .map(|(kid, k)| alloc::format!("  \"{}\": \"{}\"", hex(kid), hex(&k.to_bytes().unwrap())))
        .collect::<Vec<_>>()
        .join(",\n");
    let _ = write!(json, " \"keys\": {{\n{keys}\n }},\n \"cases\": [\n");
    let all = cose_cases();
    for (i, (id, msg)) in all.iter().enumerate() {
        let expect = match verify_sign1(&PureBackend, msg, &ks, CT) {
            Ok(v) => alloc::format!(
                "\"kid\": \"{}\", \"payload\": \"{}\"",
                hex(&v.kid),
                hex(&v.payload)
            ),
            Err(e) => alloc::format!("\"error\": \"{}\"", cose_error(e)),
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        let _ = writeln!(
            json,
            "  {{\"id\": \"{id}\", \"sign1\": \"{}\", {expect}}}{sep}",
            hex(msg)
        );
    }
    json.push_str(" ]\n}\n");
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/core/1/cose.json"
            ),
            &json,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../../conformance/vectors/core/1/cose.json"),
        json
    );
}
