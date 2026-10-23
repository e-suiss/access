extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::json::b64url_encode;
use crate::verify::PureBackend;

const TYP: &str = "access-receipt+jwt";

fn ed_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn p_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap()
}

fn kid(n: u8) -> String {
    b64url_encode(&[n; 32])
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
    k.allowed.extend([Algorithm::Ed25519, Algorithm::Es256]);
    k
}

fn token_with(header: &str, payload: &str, sign: &dyn Fn(&[u8]) -> Vec<u8>) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(&sig))
}

fn ed_sign(m: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    ed_key().sign(m).to_bytes().to_vec()
}

fn es_sign(m: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer as _;
    let s: p256::ecdsa::Signature = p_key().sign(m);
    s.normalize_s().to_bytes().to_vec()
}

fn ed_header() -> String {
    format!(r#"{{"alg":"Ed25519","kid":"{}","typ":"{TYP}"}}"#, kid(1))
}

const PAYLOAD: &str = r#"{"iss":"https://access.example","aud":"pep:shop","exp":2000,"iat":1000}"#;

struct Case {
    id: &'static str,
    row: u8,
    token: String,
    expect: Result<(), JwsError>,
}

fn h(s: &str) -> String {
    s.replace("KID1", &kid(1))
        .replace("KID2", &kid(2))
        .replace("TYP", TYP)
}

fn ed(header: &str) -> String {
    token_with(&h(header), PAYLOAD, &ed_sign)
}

fn cases() -> Vec<Case> {
    let mut out = header_cases();
    out.extend(signature_cases());
    out
}

const ED_HEADER_CASES: [(&str, u8, &str, Result<(), JwsError>); 17] = [
    (
        "alg-hs256",
        2,
        r#"{"alg":"HS256","kid":"KID1","typ":"TYP"}"#,
        Err(JwsError::Algorithm),
    ),
    (
        "alg-eddsa",
        3,
        r#"{"alg":"EdDSA","kid":"KID1","typ":"TYP"}"#,
        Err(JwsError::Algorithm),
    ),
    (
        "embedded-jwk",
        5,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP","jwk":{"kty":"OKP"}}"#,
        Err(JwsError::Header),
    ),
    (
        "jku",
        6,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP","jku":"https://evil"}"#,
        Err(JwsError::Header),
    ),
    (
        "x5u",
        6,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP","x5u":"https://evil"}"#,
        Err(JwsError::Header),
    ),
    (
        "x5c",
        7,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP","x5c":["MIIB"]}"#,
        Err(JwsError::Header),
    ),
    (
        "kid-path",
        8,
        r#"{"alg":"Ed25519","kid":"../../dev/null","typ":"TYP"}"#,
        Err(JwsError::Header),
    ),
    (
        "kid-sql",
        8,
        r#"{"alg":"Ed25519","kid":"' OR 1=1","typ":"TYP"}"#,
        Err(JwsError::Header),
    ),
    (
        "kid-unknown",
        8,
        r#"{"alg":"Ed25519","kid":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","typ":"TYP"}"#,
        Err(JwsError::UnknownKid),
    ),
    (
        "crit",
        9,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP","crit":["exp2"],"exp2":1}"#,
        Err(JwsError::Header),
    ),
    (
        "b64-false",
        10,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP","b64":false,"crit":["b64"]}"#,
        Err(JwsError::Header),
    ),
    (
        "cty-jwt",
        15,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP","cty":"JWT"}"#,
        Err(JwsError::Header),
    ),
    (
        "typ-missing",
        16,
        r#"{"alg":"Ed25519","kid":"KID1"}"#,
        Err(JwsError::Header),
    ),
    (
        "typ-other",
        16,
        r#"{"alg":"Ed25519","kid":"KID1","typ":"access-pap+jwt"}"#,
        Err(JwsError::Type),
    ),
    (
        "duplicate-alg",
        18,
        r#"{"alg":"Ed25519","alg":"none","kid":"KID1","typ":"TYP"}"#,
        Err(JwsError::Json(JsonError::Duplicate)),
    ),
    (
        "alg-not-string",
        18,
        r#"{"alg":["Ed25519"],"kid":"KID1","typ":"TYP"}"#,
        Err(JwsError::Header),
    ),
    (
        "header-not-object",
        18,
        r#"["Ed25519"]"#,
        Err(JwsError::Header),
    ),
];

fn header_cases() -> Vec<Case> {
    let es_header = h(r#"{"alg":"ES256","kid":"KID2","typ":"TYP"}"#);
    let mut out = vec![
        Case {
            id: "valid-ed25519",
            row: 0,
            token: ed(r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP"}"#),
            expect: Ok(()),
        },
        Case {
            id: "valid-es256",
            row: 0,
            token: token_with(&es_header, PAYLOAD, &es_sign),
            expect: Ok(()),
        },
        Case {
            id: "alg-none",
            row: 1,
            token: token_with(
                &h(r#"{"alg":"none","kid":"KID1","typ":"TYP"}"#),
                PAYLOAD,
                &|_| Vec::new(),
            ),
            expect: Err(JwsError::Algorithm),
        },
        Case {
            id: "alg-none-upper",
            row: 1,
            token: token_with(
                &h(r#"{"alg":"NONE","kid":"KID1","typ":"TYP"}"#),
                PAYLOAD,
                &|_| Vec::new(),
            ),
            expect: Err(JwsError::Algorithm),
        },
        Case {
            id: "key-type-mismatch",
            row: 4,
            token: token_with(
                &h(r#"{"alg":"ES256","kid":"KID1","typ":"TYP"}"#),
                PAYLOAD,
                &es_sign,
            ),
            expect: Err(JwsError::KeyType),
        },
        Case {
            id: "five-parts",
            row: 15,
            token: format!(
                "{}.x.y",
                ed(r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP"}"#)
            ),
            expect: Err(JwsError::Format),
        },
    ];
    out.extend(
        ED_HEADER_CASES
            .iter()
            .map(|(id, row, header, expect)| Case {
                id,
                row: *row,
                token: ed(header),
                expect: *expect,
            }),
    );
    out
}

fn signature_cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut add = |id, row, token, expect| {
        out.push(Case {
            id,
            row,
            token,
            expect,
        });
    };
    let good = token_with(&ed_header(), PAYLOAD, &ed_sign);
    let (input, sig) = good.rsplit_once('.').unwrap();
    add(
        "padded-signature",
        18,
        format!("{input}.{sig}=="),
        Err(JwsError::Base64),
    );
    let mut flipped = sig.to_string();
    let last = flipped.pop().unwrap();
    flipped.push(if last == 'A' { 'B' } else { 'A' });
    add(
        "signature-bit-flip",
        14,
        format!("{input}.{flipped}"),
        Err(JwsError::Signature(SignatureError::Invalid)),
    );
    let es = token_with(
        &h(r#"{"alg":"ES256","kid":"KID2","typ":"TYP"}"#),
        PAYLOAD,
        &es_sign,
    );
    let (es_input, _) = es.rsplit_once('.').unwrap();
    add(
        "psychic-signature",
        12,
        format!("{es_input}.{}", b64url_encode(&[0; 64])),
        Err(JwsError::Signature(SignatureError::ScalarRange)),
    );
    add(
        "der-signature",
        13,
        format!("{es_input}.{}", b64url_encode(&[0x30; 70])),
        Err(JwsError::Signature(SignatureError::Length)),
    );
    out
}

// CR-56
#[test]
fn attack_class_vectors() {
    let ks = keys();
    for c in cases() {
        let got = verify_compact(&PureBackend, &c.token, &ks, TYP, Origin::Native).map(|_| ());
        assert_eq!(got, c.expect, "{} (row {})", c.id, c.row);
    }
}

#[test]
fn golden_vectors_match() {
    use core::fmt::Write as _;
    let mut json = String::from(
        "{\n \"rule\": \"CR-56\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"verify.jws_compact\",\n \"typ\": \"access-receipt+jwt\",\n \"keys\": {\n",
    );
    let _ = writeln!(
        json,
        "  \"{}\": \"{}\",",
        kid(1),
        b64url_encode(&ed_key().verifying_key().to_bytes())
    );
    let _ = writeln!(
        json,
        "  \"{}\": \"{}\"",
        kid(2),
        b64url_encode(p_key().verifying_key().to_sec1_point(false).as_bytes())
    );
    json.push_str(" },\n \"cases\": [\n");
    let all = cases();
    for (i, c) in all.iter().enumerate() {
        let expect = match &c.expect {
            Ok(()) => "accept".to_string(),
            Err(e) => format!("reject: {e}"),
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        let _ = writeln!(
            json,
            "  {{\"id\": \"{}\", \"row\": {}, \"token\": \"{}\", \"expect\": \"{expect}\"}}{sep}",
            c.id, c.row, c.token
        );
    }
    json.push_str(" ]\n}\n");
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/core/1/jose-attack-classes.json"
            ),
            &json,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../../conformance/vectors/core/1/jose-attack-classes.json"),
        json
    );
}

// CR-56 row 17, CR-55 m.9
#[test]
fn claim_rules() {
    let rules = ClaimRules {
        issuer: "https://access.example",
        audience: "pep:shop",
        now: 1_500_000,
        skew_ms: 60_000,
    };
    assert!(check_claims(PAYLOAD.as_bytes(), &rules).is_ok());
    let at = |now| ClaimRules { now, ..rules };
    assert_eq!(
        check_claims(PAYLOAD.as_bytes(), &at(2_059_999)).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        check_claims(PAYLOAD.as_bytes(), &at(2_060_000)).map(|_| ()),
        Err(ClaimError::Expired)
    );
    assert_eq!(
        check_claims(PAYLOAD.as_bytes(), &at(939_000)).map(|_| ()),
        Err(ClaimError::NotYetValid)
    );
    let p = |s: &str| check_claims(s.as_bytes(), &rules).map(|_| ());
    assert_eq!(
        p(r#"{"iss":"https://access.example","aud":"pep:bank","exp":2000}"#),
        Err(ClaimError::Audience)
    );
    assert_eq!(
        p(r#"{"iss":"https://access.example","aud":["pep:bank","pep:shop"],"exp":2000}"#),
        Ok(())
    );
    assert_eq!(
        p(r#"{"iss":"https://access.example","aud":[],"exp":2000}"#),
        Err(ClaimError::Audience)
    );
    assert_eq!(
        p(r#"{"iss":"https://evil","aud":"pep:shop","exp":2000}"#),
        Err(ClaimError::Issuer)
    );
    assert_eq!(
        p(r#"{"iss":"https://access.example","aud":"pep:shop"}"#),
        Err(ClaimError::Expired)
    );
    assert_eq!(
        p(r#"{"iss":"https://access.example","aud":"pep:shop","exp":"2000"}"#),
        Err(ClaimError::Time)
    );
    assert_eq!(
        p(r#"{"iss":"https://access.example","aud":"pep:shop","exp":9223372036854775807}"#),
        Err(ClaimError::Time)
    );
    assert_eq!(
        p(r#"{"iss":"https://access.example","aud":"pep:shop","exp":2000.5}"#),
        Err(ClaimError::Json(JsonError::Number))
    );
}

#[test]
fn external_tokens_may_carry_high_s() {
    let header = r#"{"alg":"ES256","kid":"KID2","typ":"TYP"}"#
        .replace("KID2", &kid(2))
        .replace("TYP", TYP);
    let high = |m: &[u8]| {
        let low = es_sign(m);
        let mut n = crate::verify::P256_N;
        let mut borrow = false;
        for i in (0..32).rev() {
            let (d1, b1) = n[i].overflowing_sub(low[32 + i]);
            let (d2, b2) = d1.overflowing_sub(u8::from(borrow));
            n[i] = d2;
            borrow = b1 || b2;
        }
        [low[..32].to_vec(), n.to_vec()].concat()
    };
    let t = token_with(&header, PAYLOAD, &high);
    assert!(verify_compact(&PureBackend, &t, &keys(), TYP, Origin::External).is_ok());
    assert_eq!(
        verify_compact(&PureBackend, &t, &keys(), TYP, Origin::Native).map(|_| ()),
        Err(JwsError::Signature(SignatureError::HighS))
    );
}

// CR-56 row 11
#[test]
fn invalid_keys_are_refused_by_the_key_set() {
    let mut ks = KeySet::default();
    let mut off_curve = p_key()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    off_curve[64] ^= 1;
    assert_eq!(
        ks.insert([1; 32], PublicKey::P256(off_curve)),
        Err(SignatureError::NonCanonicalKey)
    );
    let compressed = p_key()
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(
        ks.insert([1; 32], PublicKey::P256(compressed)),
        Err(SignatureError::NonCanonicalKey)
    );
    let mut small = [0_u8; 32];
    small[0] = 1;
    assert_eq!(
        ks.insert([1; 32], PublicKey::Ed25519(small)),
        Err(SignatureError::SmallOrderKey)
    );
    let mut non_canonical = [0xff_u8; 32];
    non_canonical[31] = 0x7f;
    assert_eq!(
        ks.insert([1; 32], PublicKey::Ed25519(non_canonical)),
        Err(SignatureError::NonCanonicalKey)
    );
    assert_eq!(
        ks.insert(
            [1; 32],
            PublicKey::Ed25519(ed_key().verifying_key().to_bytes())
        ),
        Ok(())
    );
    assert_eq!(ks.keys.len(), 1);
}
