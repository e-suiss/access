use access_kernel::json::b64url_encode;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

use super::*;

const NOW: u64 = 1_800_000_000_000;
const ISS: &str = "https://idp.example";
const AS: &str = "https://as.example/realms/acme";

fn key() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()
}

fn public(k: &EcdsaKeyPair) -> PublicKey {
    PublicKey::P256(k.public_key().as_ref().to_vec())
}

fn keys(k: &EcdsaKeyPair) -> KeySet {
    access_kernel::claim::Pinned {
        iss: String::from(ISS),
        aud: String::from(AS),
        keys: vec![public(k)],
    }
    .key_set()
}

fn jwt(k: &EcdsaKeyPair, typ: &str, claims: &serde_json::Value) -> String {
    let header =
        json!({ "alg": "ES256", "kid": b64url_encode(&thumbprint(&public(k))), "typ": typ });
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

fn jag(extra: &[(&str, serde_json::Value)]) -> serde_json::Value {
    let mut c = json!({
        "iss": ISS, "sub": "U019488227", "aud": AS, "client_id": "cli_agent",
        "jti": "9e43f81b64a33f20116179", "iat": NOW / 1000, "exp": NOW / 1000 + 300,
        "resource": "https://mcp.example/mcp", "email": "user@example.com",
        "scope": "chat.read",
    });
    if let serde_json::Value::Object(m) = &mut c {
        for (k, v) in extra {
            m.insert(String::from(*k), v.clone());
        }
    }
    c
}

fn rules() -> AssertionRules<'static> {
    AssertionRules {
        iss: ISS,
        typ: ID_JAG_TYP,
        audience: AS,
        client_id: Some("cli_agent"),
        now_ms: NOW,
    }
}

// AG-29, MD-18, E26, §11.11.3, OP-154 m.3 (n), (q), Ek B 4189, 4563, 4653
#[test]
fn an_assertion_passes_the_five_checks_and_keeps_no_email() {
    let k = key();
    let a = verify_assertion(&jwt(&k, ID_JAG_TYP, &jag(&[])), &keys(&k), &rules()).unwrap();
    assert_eq!(a.sub, "U019488227");
    assert_eq!(a.jti, "9e43f81b64a33f20116179");
    assert_eq!(a.resource.as_deref(), Some("https://mcp.example/mcp"));
    assert!(!format!("{a:?}").contains("user@example.com"));

    let other = key();
    let cases = [
        (
            jwt(&other, ID_JAG_TYP, &jag(&[])),
            AssertionError::Signature,
        ),
        (jwt(&k, JWT_TYP, &jag(&[])), AssertionError::Signature),
        (
            jwt(
                &k,
                ID_JAG_TYP,
                &jag(&[("aud", json!("https://else.example"))]),
            ),
            AssertionError::Audience,
        ),
        (
            jwt(
                &k,
                ID_JAG_TYP,
                &jag(&[("aud", json!([AS, "https://else.example"]))]),
            ),
            AssertionError::Audience,
        ),
        (
            jwt(&k, ID_JAG_TYP, &jag(&[("client_id", json!("cli_other"))])),
            AssertionError::Client,
        ),
        (
            jwt(&k, ID_JAG_TYP, &jag(&[("exp", json!(NOW / 1000 + 301))])),
            AssertionError::Time,
        ),
        (
            jwt(&k, ID_JAG_TYP, &jag(&[("exp", json!(NOW / 1000 - 120))])),
            AssertionError::Time,
        ),
        (
            jwt(&k, ID_JAG_TYP, &jag(&[("jti", json!(""))])),
            AssertionError::Claims,
        ),
    ];
    for (token, want) in cases {
        assert_eq!(verify_assertion(&token, &keys(&k), &rules()), Err(want));
    }
}

// AG-29, OP-154 m.3 (n), Ek B 4190
#[test]
fn a_jti_slot_is_the_same_for_the_same_assertion_only() {
    let k = key();
    let a = verify_assertion(&jwt(&k, ID_JAG_TYP, &jag(&[])), &keys(&k), &rules()).unwrap();
    let again = a.clone();
    assert_eq!(jti_slot(&a), jti_slot(&again));
    let other = Assertion {
        jti: String::from("another"),
        ..a.clone()
    };
    assert_ne!(jti_slot(&a).unwrap().1, jti_slot(&other).unwrap().1);
    let elsewhere = Assertion {
        iss: String::from("https://other-idp.example"),
        ..a
    };
    assert_ne!(jti_slot(&other).unwrap().1, jti_slot(&elsewhere).unwrap().1);
}

// AG-25, §9.9.4, L22, Ek B 4212, 4608
#[test]
fn act_is_read_to_sixteen_levels_and_never_believed() {
    let mut nested = serde_json::Value::Null;
    for level in 0..4 {
        nested = if nested.is_null() {
            json!({ "sub": format!("a{level}") })
        } else {
            json!({ "sub": format!("a{level}"), "act": nested })
        };
    }
    assert_eq!(act_depth(&json!({ "sub": "p", "act": nested })), Ok(4));
    assert_eq!(act_depth(&json!({ "sub": "p" })), Ok(0));
    let mut deep = json!({ "sub": "x" });
    for _ in 0..MAX_ACT_DEPTH {
        deep = json!({ "sub": "x", "act": deep });
    }
    assert_eq!(act_depth(&json!({ "act": deep })), Err(ActError::Depth));
    assert_eq!(
        act_depth(&json!({ "act": { "iss": "x" } })),
        Err(ActError::Shape)
    );
}

// §11.21.2, §11.21.3, OP-154 m.3 (m), (cc), Ek B 4146, 4653
#[test]
fn token_types_are_a_closed_registry() {
    assert_eq!(
        requested(None),
        Some(Requested::Projection {
            issued: ACCESS_TOKEN
        })
    );
    assert_eq!(
        requested(Some(JWT)),
        Some(Requested::Projection { issued: JWT })
    );
    assert_eq!(requested(Some(ID_JAG)), Some(Requested::IdJag));
    assert_eq!(requested(Some(TXN_TOKEN)), Some(Requested::Txn));
    assert_eq!(requested(Some(ID_TOKEN)), Some(Requested::IdToken));
    assert_eq!(requested(Some(REFRESH_TOKEN)), Some(Requested::Refresh));
    assert_eq!(requested(Some(SAML2)), None);
    assert_eq!(subject_kind(SAML2), Some(SubjectKind::Saml));
    assert_eq!(subject_kind(TXN_TOKEN), None);
    assert_eq!(subject_kind(ID_JAG), None);
    assert_eq!(typ_role("at+jwt"), Some(TypRole::Projection));
    assert_eq!(typ_role(ID_JAG_TYP), Some(TypRole::Assertion));
    assert_eq!(typ_role(TXN_TYP), Some(TypRole::AuditOnly));
    for t in [
        WIT_TYP,
        WPT_TYP,
        CLIENT_ATTESTATION_TYP,
        CLIENT_ATTESTATION_POP_TYP,
    ] {
        assert_eq!(typ_role(t), Some(TypRole::Interface));
    }
    assert_eq!(typ_role("dpop+jwt"), None);
}

// MD-18, L6, OP-154 m.3 (n), (o), Ek B 4188, 4155, 4635
#[test]
fn issued_assertions_carry_no_authority() {
    let jag = id_jag_claims(&IdJagFacts {
        issuer: AS,
        sub: "pw-p",
        audience: "https://as.chat.example",
        client_id: "cli_agent",
        resource: "https://mcp.chat.example",
        scope: Some("chat.read"),
        jti: "j1",
        now_ms: NOW,
        until_ms: NOW + 900_000,
    });
    let c: serde_json::Value = serde_json::from_slice(&jag).unwrap();
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 300);
    assert!(c.get("authorization_details").is_none() && c.get("act").is_none());
    let short = id_jag_claims(&IdJagFacts {
        issuer: AS,
        sub: "pw-p",
        audience: "https://as.chat.example",
        client_id: "cli_agent",
        resource: "https://mcp.chat.example",
        scope: None,
        jti: "j2",
        now_ms: NOW,
        until_ms: NOW + 60_000,
    });
    let c: serde_json::Value = serde_json::from_slice(&short).unwrap();
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 60);
    assert!(c.get("scope").is_none());
    let txn = txn_claims(&TxnFacts {
        issuer: AS,
        audience: AS,
        sub: "pw-p",
        txn: "t1",
        exercise: "sha-256:abc",
        intent: Some("sha-256:def"),
        now_ms: NOW,
    });
    let c: serde_json::Value = serde_json::from_slice(&txn).unwrap();
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 60);
    assert_eq!(c["tctx"]["exercise"], "sha-256:abc");
    assert_eq!(c["tctx"]["intent"], "sha-256:def");
    assert!(c.get("authorization_details").is_none() && c.get("cnf").is_none());
}
