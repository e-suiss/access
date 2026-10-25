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

/// The metadata allowlist of every case that does not name its own.
const METADATA: &[Algorithm] = &[Algorithm::Ed25519, Algorithm::Es256];

fn cases() -> Vec<(Case, &'static [Algorithm])> {
    let mut out: Vec<(Case, &'static [Algorithm])> = header_cases()
        .into_iter()
        .chain(signature_cases())
        .map(|c| (c, METADATA))
        .collect();
    out.extend(downgrade_cases());
    out
}

// CR-56 rows 2-4, CR-7, §10.4.5, G46
fn downgrade_cases() -> Vec<(Case, &'static [Algorithm])> {
    let es_header = h(r#"{"alg":"ES256","kid":"KID2","typ":"TYP"}"#);
    let mut out = vec![
        (
            Case {
                id: "metadata-es256-alg-ed25519",
                row: 3,
                token: ed(r#"{"alg":"Ed25519","kid":"KID1","typ":"TYP"}"#),
                expect: Err(JwsError::Algorithm),
            },
            &[Algorithm::Es256][..],
        ),
        (
            Case {
                id: "metadata-ed25519-alg-es256",
                row: 3,
                token: token_with(&es_header, PAYLOAD, &es_sign),
                expect: Err(JwsError::Algorithm),
            },
            &[Algorithm::Ed25519][..],
        ),
        (
            Case {
                id: "p256-key-alg-ed25519",
                row: 4,
                token: ed(r#"{"alg":"Ed25519","kid":"KID2","typ":"TYP"}"#),
                expect: Err(JwsError::KeyType),
            },
            METADATA,
        ),
        (
            Case {
                id: "alg-hs256-p256-key",
                row: 2,
                token: token_with(
                    &h(r#"{"alg":"HS256","kid":"KID2","typ":"TYP"}"#),
                    PAYLOAD,
                    &|_| vec![0x5a; 32],
                ),
                expect: Err(JwsError::Algorithm),
            },
            METADATA,
        ),
    ];
    for (id, alg) in [
        ("alg-rs256", "RS256"),
        ("alg-ps256", "PS256"),
        ("alg-rsa1-5", "RSA1_5"),
    ] {
        out.push((
            Case {
                id,
                row: 3,
                token: token_with(
                    &h(&format!(r#"{{"alg":"{alg}","kid":"KID2","typ":"TYP"}}"#)),
                    PAYLOAD,
                    &|_| vec![0x5a; 256],
                ),
                expect: Err(JwsError::Algorithm),
            },
            METADATA,
        ));
    }
    out
}

fn cose_ids(algs: &[Algorithm]) -> String {
    algs.iter()
        .map(|a| a.cose().to_string())
        .collect::<Vec<_>>()
        .join(", ")
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
    for (c, allowed) in cases() {
        let mut ks = keys();
        ks.allowed = allowed.iter().copied().collect();
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
    let _ = write!(
        json,
        " }},\n \"allowed\": [{}],\n \"cases\": [\n",
        cose_ids(METADATA)
    );
    let all = cases();
    for (i, (c, allowed)) in all.iter().enumerate() {
        let expect = match &c.expect {
            Ok(()) => "accept".to_string(),
            Err(e) => format!("reject: {e}"),
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        let own = if *allowed == METADATA {
            String::new()
        } else {
            format!(", \"allowed\": [{}]", cose_ids(allowed))
        };
        let _ = writeln!(
            json,
            "  {{\"id\": \"{}\", \"row\": {}{own}, \"token\": \"{}\", \"expect\": \"{expect}\"}}{sep}",
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
        check_claims(PAYLOAD.as_bytes(), &at(2_060_000)).map(|_| ()),
        Ok(())
    );
    // OP-122 m.3
    assert_eq!(
        check_claims(PAYLOAD.as_bytes(), &at(2_060_001)).map(|_| ()),
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

fn nested(depth: usize) -> String {
    format!(
        r#"{{"iss":"https://access.example","aud":"pep:shop","exp":2000,"x":{}0{}}}"#,
        "[".repeat(depth),
        "]".repeat(depth)
    )
}

// OP-122 m.3, m.7, OP-117 m.17
fn claim_cases() -> Vec<(&'static str, String, u64)> {
    let base = |rest: &str| format!(r#"{{"iss":"https://access.example","aud":"pep:shop"{rest}}}"#);
    vec![
        ("valid", PAYLOAD.to_string(), 1_500_000),
        ("exp-edge-inclusive", PAYLOAD.to_string(), 2_060_000),
        ("exp-past", PAYLOAD.to_string(), 2_060_001),
        ("exp-missing", base(""), 1_500_000),
        ("exp-not-integer", base(r#","exp":"2000""#), 1_500_000),
        (
            "exp-overflow",
            base(r#","exp":9223372036854775807"#),
            1_500_000,
        ),
        ("exp-fraction", base(r#","exp":2000.5"#), 1_500_000),
        ("exp-negative", base(r#","exp":-1"#), 1_500_000),
        ("nbf-negative", base(r#","exp":2000,"nbf":-1"#), 1_500_000),
        ("iat-negative", base(r#","exp":2000,"iat":-1"#), 1_500_000),
        ("nbf-edge", base(r#","exp":2000,"nbf":1560"#), 1_500_000),
        ("nbf-future", base(r#","exp":2000,"nbf":1561"#), 1_500_000),
        ("iat-edge", base(r#","exp":2000,"iat":1560"#), 1_500_000),
        ("iat-future", base(r#","exp":2000,"iat":1561"#), 1_500_000),
        (
            "iss-other",
            r#"{"iss":"https://evil","aud":"pep:shop","exp":2000}"#.to_string(),
            1_500_000,
        ),
        (
            "iss-missing",
            r#"{"aud":"pep:shop","exp":2000}"#.to_string(),
            1_500_000,
        ),
        (
            "aud-other",
            r#"{"iss":"https://access.example","aud":"pep:bank","exp":2000}"#.to_string(),
            1_500_000,
        ),
        (
            "aud-array-contains",
            r#"{"iss":"https://access.example","aud":["pep:bank","pep:shop"],"exp":2000}"#
                .to_string(),
            1_500_000,
        ),
        (
            "aud-empty-array",
            r#"{"iss":"https://access.example","aud":[],"exp":2000}"#.to_string(),
            1_500_000,
        ),
        (
            "aud-missing",
            r#"{"iss":"https://access.example","exp":2000}"#.to_string(),
            1_500_000,
        ),
        ("json-depth-32", nested(31), 1_500_000),
        ("json-depth-33", nested(32), 1_500_000),
        (
            "json-duplicate-member",
            r#"{"iss":"https://access.example","aud":"pep:shop","exp":2000,"exp":3000}"#
                .to_string(),
            1_500_000,
        ),
    ]
}

fn claim_result(token: &str, now: u64) -> Result<(), String> {
    let v = verify_compact(&PureBackend, token, &keys(), TYP, Origin::Native)
        .map_err(|e| format!("{e}"))?;
    let rules = ClaimRules {
        issuer: "https://access.example",
        audience: "pep:shop",
        now,
        skew_ms: 60_000,
    };
    check_claims(&v.payload, &rules)
        .map(|_| ())
        .map_err(|e| format!("{e}"))
}

// OP-122 m.3, m.7
#[test]
fn jwt_claim_vectors_match() {
    use core::fmt::Write as _;
    let all = claim_cases();
    let got: alloc::collections::BTreeMap<&str, Result<(), String>> = all
        .iter()
        .map(|(id, payload, now)| {
            (
                *id,
                claim_result(&token_with(&ed_header(), payload, &ed_sign), *now),
            )
        })
        .collect();
    for id in [
        "valid",
        "exp-edge-inclusive",
        "nbf-edge",
        "iat-edge",
        "aud-array-contains",
        "json-depth-32",
    ] {
        assert_eq!(got[id], Ok(()), "{id}");
    }
    assert_eq!(got["exp-past"], Err("expired".to_string()));
    for id in ["exp-negative", "nbf-negative", "iat-negative"] {
        assert_eq!(got[id], Err("bad time claim".to_string()), "{id}");
    }
    assert_eq!(
        got["json-depth-33"],
        Err("payload: nesting too deep".to_string())
    );
    let mut json = format!(
        "{{\n \"rule\": \"OP-122\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"verify.jws_compact\",\n \"typ\": \"{TYP}\",\n \"keys\": {{\n  \"{}\": \"{}\"\n }},\n \"allowed\": [{}],\n \"claims\": {{\"issuer\": \"https://access.example\", \"audience\": \"pep:shop\", \"now\": 1500000, \"skew_ms\": 60000}},\n \"cases\": [\n",
        kid(1),
        b64url_encode(&ed_key().verifying_key().to_bytes()),
        cose_ids(&[Algorithm::Ed25519]),
    );
    let mut lines = Vec::new();
    for (id, payload, now) in &all {
        let expect = match &got[id] {
            Ok(()) => "accept".to_string(),
            Err(e) => format!("reject: {e}"),
        };
        let claims = if *now == 1_500_000 {
            String::new()
        } else {
            format!(
                ", \"claims\": {{\"issuer\": \"https://access.example\", \"audience\": \"pep:shop\", \"now\": {now}, \"skew_ms\": 60000}}"
            )
        };
        lines.push(format!(
            "  {{\"id\": \"{id}\"{claims}, \"token\": \"{}\", \"expect\": \"{expect}\"}}",
            token_with(&ed_header(), payload, &ed_sign)
        ));
    }
    json.push_str(&lines.join(",\n"));
    let _ = write!(json, "\n ]\n}}\n");
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/core/1/jwt-claims.json"
            ),
            &json,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../../conformance/vectors/core/1/jwt-claims.json"),
        json
    );
}
