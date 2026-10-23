use alloc::string::String;
use alloc::vec::Vec;

use super::*;

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

#[derive(serde::Deserialize)]
struct Strict {
    cases: Vec<StrictCase>,
}

#[derive(serde::Deserialize)]
struct StrictCase {
    id: String,
    public_key: String,
    message: String,
    signature: String,
    result: String,
    reason: String,
}

// CR-53, CR-56 row 14
#[test]
fn ed25519_speccheck_cases_follow_cr53() {
    let v: Strict = serde_json::from_str(include_str!(
        "../../../../conformance/vectors/core/1/ed25519-strict.json"
    ))
    .unwrap();
    assert_eq!(v.cases.len(), 12);
    for c in &v.cases {
        let got = ed25519(
            &PureBackend,
            &bytes(&c.public_key),
            &bytes(&c.message),
            &bytes(&c.signature),
        );
        let reason = match got {
            Ok(()) => "ok",
            Err(SignatureError::NonCanonicalKey) => "non_canonical_a",
            Err(SignatureError::NonCanonicalR) => "non_canonical_r",
            Err(SignatureError::UnreducedS) => "s_not_reduced",
            Err(SignatureError::SmallOrderKey) => "small_order_a",
            Err(SignatureError::SmallOrderR) => "small_order_r",
            Err(SignatureError::Invalid) => "equation",
            Err(e) => panic!("{}: unexpected {e:?}", c.id),
        };
        assert_eq!(
            (got.is_ok(), reason),
            (c.result == "accept", c.reason.as_str()),
            "{}",
            c.id
        );
    }
}

#[derive(serde::Deserialize)]
struct Wycheproof {
    #[serde(rename = "testGroups")]
    groups: Vec<Group>,
}

#[derive(serde::Deserialize)]
struct Group {
    #[serde(rename = "publicKey")]
    key: Key,
    tests: Vec<Test>,
}

#[derive(serde::Deserialize)]
struct Key {
    #[serde(default)]
    pk: String,
    #[serde(default)]
    uncompressed: String,
}

#[derive(serde::Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    id: u32,
    msg: String,
    sig: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

// CR-51, CR-53
#[test]
fn ed25519_wycheproof() {
    let w: Wycheproof = serde_json::from_str(include_str!(
        "../../../../conformance/vectors/external/wycheproof-ed25519_test.json"
    ))
    .unwrap();
    let mut n = 0;
    for g in &w.groups {
        for t in &g.tests {
            let ok = ed25519(
                &PureBackend,
                &bytes(&g.key.pk),
                &bytes(&t.msg),
                &bytes(&t.sig),
            )
            .is_ok();
            assert_eq!(ok, t.result == "valid", "tcId {}", t.id);
            n += 1;
        }
    }
    assert_eq!(n, 151);
}

// CR-51, CR-55 m.1, CR-56 rows 12–13
#[test]
fn p256_wycheproof_and_high_s() {
    let w: Wycheproof = serde_json::from_str(include_str!(
        "../../../../conformance/vectors/external/wycheproof-ecdsa_secp256r1_sha256_p1363_test.json"
    ))
    .unwrap();
    let (mut n, mut high_s) = (0, 0);
    for g in &w.groups {
        let key = bytes(&g.key.uncompressed);
        for t in &g.tests {
            let sig = bytes(&t.sig);
            let ok = p256(&PureBackend, &key, &bytes(&t.msg), &sig, false).is_ok();
            assert_eq!(ok, t.result == "valid", "tcId {} {:?}", t.id, t.flags);
            if ok && sig.len() == 64 && sig[32..] > P256_HALF_N[..] {
                assert_eq!(
                    p256(&PureBackend, &key, &bytes(&t.msg), &sig, true),
                    Err(SignatureError::HighS)
                );
                high_s += 1;
            }
            n += 1;
        }
    }
    assert!(n > 200 && high_s > 0, "{n} tests, {high_s} high-S");
}

#[test]
fn psychic_signature_is_rejected_before_the_backend() {
    struct Yes;
    impl Backend for Yes {
        fn ed25519(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool {
            true
        }
        fn p256(&self, _: &[u8], _: &[u8], _: &[u8; 64]) -> bool {
            true
        }
    }
    assert_eq!(
        p256(&Yes, &[4; 65], b"m", &[0; 64], false),
        Err(SignatureError::ScalarRange)
    );
    let mut s_eq_n = [1_u8; 64];
    s_eq_n[32..].copy_from_slice(&P256_N);
    assert_eq!(
        p256(&Yes, &[4; 65], b"m", &s_eq_n, false),
        Err(SignatureError::ScalarRange)
    );
    assert_eq!(
        p256(&Yes, &[4; 65], b"m", &[1; 63], false),
        Err(SignatureError::Length)
    );
}
