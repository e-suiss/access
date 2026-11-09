#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use access_kernel::json::b64url_encode;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use rcgen::{
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
    string::Ia5String,
};

use super::*;
use crate::domain::testing::Ca;

const NOW: u64 = 1_800_000_000_000;
const AS: &str = "https://acme.id.test";
const FRESH: Freshness = Freshness {
    fetched_ms: NOW - 1_000,
    now_ms: NOW,
};

fn key() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()
}

fn bundle_doc(k: &EcdsaKeyPair, kid: &str, roots: &[Vec<u8>], hint: u64) -> String {
    let p = k.public_key().as_ref();
    let mut keys = vec![format!(
        r#"{{"use":"jwt-svid","kty":"EC","crv":"P-256","kid":"{kid}","x":"{}","y":"{}"}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    )];
    for r in roots {
        keys.push(format!(
            r#"{{"use":"x509-svid","kty":"EC","crv":"P-256","x5c":["{}"]}}"#,
            crate::domain::testing::b64_std(r)
        ));
    }
    format!(
        r#"{{"keys":[{}],"spiffe_sequence":1,"spiffe_refresh_hint":{hint}}}"#,
        keys.join(",")
    )
}

fn jwt(k: &EcdsaKeyPair, header: &str, claims: &str) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(claims.as_bytes())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

fn claims(sub: &str, aud: &str, exp_s: u64) -> String {
    format!(
        r#"{{"sub":"{sub}","aud":["{aud}"],"exp":{exp_s},"iat":{}}}"#,
        NOW / 1000
    )
}

const H: &str = r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#;
const SUB: &str = "spiffe://acme.example/agent/finance/a1";

// AG-30, §11.12.1, Ek B 4133, 4183, 4546
#[test]
fn a_jwt_svid_follows_the_spiffe_rules() {
    let k = key();
    let b = Bundle::parse("acme.example", bundle_doc(&k, "k1", &[], 300).as_bytes()).unwrap();
    let exp = NOW / 1000 + 120;
    let token = jwt(&k, H, &claims(SUB, AS, exp));
    assert_eq!(jwt_subject(&token).unwrap().as_str(), SUB);
    let ok = verify_jwt(&token, &b, AS, FRESH).unwrap();
    assert_eq!(ok.id.as_str(), SUB);
    assert_eq!(ok.exp_ms, Some(exp * 1000));
    assert!(ok.replay_key.is_some());
    let cases = [
        (claims(SUB, "https://other.test", exp), SvidError::Audience),
        (
            format!(r#"{{"sub":"{SUB}","aud":["{AS}","x"],"exp":{exp}}}"#),
            SvidError::Audience,
        ),
        (
            format!(r#"{{"sub":"{SUB}","exp":{exp}}}"#),
            SvidError::Audience,
        ),
        (
            format!(r#"{{"sub":"{SUB}","aud":"{AS}"}}"#),
            SvidError::Time,
        ),
        (claims(SUB, AS, NOW / 1000 - 120), SvidError::Time),
        (claims(SUB, AS, NOW / 1000 + 3_600), SvidError::Time),
        (
            claims("spiffe://beta.example/agent", AS, exp),
            SvidError::Id,
        ),
        (claims("wimse://acme.example/agent", AS, exp), SvidError::Id),
    ];
    for (c, want) in cases {
        assert_eq!(verify_jwt(&jwt(&k, H, &c), &b, AS, FRESH), Err(want), "{c}");
    }
    for h in [
        r#"{"alg":"RS256","kid":"k1"}"#,
        r#"{"alg":"none","kid":"k1"}"#,
        r#"{"alg":"ES256","kid":"k1","typ":"wit+jwt"}"#,
        r#"{"alg":"ES256","kid":"k1","jku":"https://x"}"#,
    ] {
        assert_eq!(
            verify_jwt(&jwt(&k, h, &claims(SUB, AS, exp)), &b, AS, FRESH),
            Err(SvidError::Format),
            "{h}"
        );
    }
    let unknown = jwt(&k, r#"{"alg":"ES256","kid":"k2"}"#, &claims(SUB, AS, exp));
    assert_eq!(verify_jwt(&unknown, &b, AS, FRESH), Err(SvidError::Key));
    let forged = jwt(&key(), H, &claims(SUB, AS, exp));
    assert_eq!(
        verify_jwt(&forged, &b, AS, FRESH),
        Err(SvidError::Signature)
    );
}

// OP-154 m.3 (r), AG-30
#[test]
fn an_expired_bundle_refuses_jwt_svids() {
    let k = key();
    let b = Bundle::parse("acme.example", bundle_doc(&k, "k1", &[], 300).as_bytes()).unwrap();
    let token = jwt(&k, H, &claims(SUB, AS, NOW / 1000 + 120));
    let fresh_enough = Freshness {
        fetched_ms: NOW - 600_000,
        now_ms: NOW,
    };
    assert!(verify_jwt(&token, &b, AS, fresh_enough).is_ok());
    let stale = Freshness {
        fetched_ms: NOW - 600_001,
        now_ms: NOW,
    };
    assert_eq!(verify_jwt(&token, &b, AS, stale), Err(SvidError::Key));
}

fn svid(ca: &Ca, uris: &[&str], usage: &[KeyUsagePurpose], is_ca: IsCa) -> Vec<u8> {
    ca.leaf(|p| {
        p.subject_alt_names = uris
            .iter()
            .map(|u| SanType::URI(Ia5String::try_from(*u).unwrap()))
            .collect();
        p.key_usages = usage.to_vec();
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.is_ca = is_ca;
    })
}

// AG-30, §11.15, Ek B 4133, 4447
#[test]
fn an_x509_svid_is_a_leaf_with_one_spiffe_id() {
    let ca = Ca::new(&PKCS_ECDSA_P256_SHA256);
    let k = key();
    let b = Bundle::parse(
        "acme.example",
        bundle_doc(&k, "k1", std::slice::from_ref(&ca.root), 300).as_bytes(),
    )
    .unwrap();
    let ds = || vec![KeyUsagePurpose::DigitalSignature];
    let leaf = svid(&ca, &[SUB], &ds(), IsCa::ExplicitNoCa);
    assert_eq!(x509_subject(&leaf).unwrap().as_str(), SUB);
    let ok = verify_x509(&[leaf], &b, FRESH).unwrap();
    assert_eq!(ok.id.as_str(), SUB);
    assert_eq!(ok.replay_key, None);
    let refused = [
        (
            svid(
                &ca,
                &[SUB, "spiffe://acme.example/b"],
                &ds(),
                IsCa::ExplicitNoCa,
            ),
            SvidError::Id,
        ),
        (
            svid(&ca, &["spiffe://beta.example/a"], &ds(), IsCa::ExplicitNoCa),
            SvidError::Id,
        ),
        (svid(&ca, &[SUB], &ds(), IsCa::NoCa), SvidError::Format),
        (
            svid(
                &ca,
                &[SUB],
                &[KeyUsagePurpose::KeyEncipherment],
                IsCa::ExplicitNoCa,
            ),
            SvidError::Format,
        ),
    ];
    for (leaf, want) in refused {
        assert_eq!(verify_x509(&[leaf], &b, FRESH), Err(want));
    }
    let foreign = Ca::new(&PKCS_ECDSA_P256_SHA256);
    let other = svid(&foreign, &[SUB], &ds(), IsCa::ExplicitNoCa);
    assert_eq!(verify_x509(&[other], &b, FRESH), Err(SvidError::Signature));
    let stale = Freshness {
        fetched_ms: NOW - 600_001,
        now_ms: NOW,
    };
    let leaf = svid(&ca, &[SUB], &ds(), IsCa::ExplicitNoCa);
    assert_eq!(verify_x509(&[leaf], &b, stale), Err(SvidError::Key));
}
