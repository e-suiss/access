use access_kernel::json::b64url_encode;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::{Signer as _, SoftSigner};

use super::*;

fn sec1(k: &SoftSigner) -> [u8; 65] {
    match k.public_key() {
        PublicKey::P256(p) if p.len() == 65 => <[u8; 65]>::try_from(p.as_slice()).unwrap(),
        PublicKey::P256(p) => panic!("compressed point of {} bytes", p.len()),
        _ => panic!("not P-256"),
    }
}

pub(crate) fn proof(k: &SoftSigner, jti: &str, with_key: bool, typ: &str) -> String {
    let p = sec1(k);
    let header = json!({ "alg": "ES256", "typ": typ });
    let mut payload = json!({ "jti": jti, "iat": 1 });
    if with_key {
        payload["key"] = json!({
            "kty": "EC", "crv": "P-256",
            "x": b64url_encode(&p[1..33]), "y": b64url_encode(&p[33..]),
        });
    }
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes())
    );
    let sig = k.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(&sig))
}

// TN-33, OP-153 m.3 (y)
#[test]
fn a_registration_proof_names_its_key_and_verifies_with_it() {
    let (k, _) = SoftSigner::generate_p256().unwrap();
    let p = parse(&proof(&k, "c1", true, "dbsc+jwt")).unwrap();
    assert_eq!(p.jti, "c1");
    let key = p.key.unwrap();
    assert_eq!(key, sec1(&k));
    p.verify(&key).unwrap();
}

// TN-33
#[test]
fn a_proof_from_another_key_is_refused() {
    let (k, _) = SoftSigner::generate_p256().unwrap();
    let (thief, _) = SoftSigner::generate_p256().unwrap();
    let p = parse(&proof(&thief, "c2", false, "dbsc+jwt")).unwrap();
    assert_eq!(p.verify(&sec1(&k)), Err(ProofError::Signature));
}

// TN-33
#[test]
fn malformed_and_foreign_proofs_are_refused() {
    let (k, _) = SoftSigner::generate_p256().unwrap();
    assert_eq!(
        parse(&proof(&k, "c", true, "JWT")).unwrap_err(),
        ProofError::Algorithm
    );
    assert_eq!(parse("a.b").unwrap_err(), ProofError::Malformed);
    assert_eq!(
        parse(&"a".repeat(MAX_PROOF + 1)).unwrap_err(),
        ProofError::Malformed
    );
    let mut tampered = proof(&k, "c", true, "dbsc+jwt");
    tampered.push('A');
    assert!(parse(&tampered).and_then(|p| p.verify(&sec1(&k))).is_err());
}

// TN-33, OP-153 m.3 (y)
#[test]
fn a_tied_session_needs_its_live_bound_cookie() {
    let d = [7_u8; 32];
    assert!(bound_ok(false, None, None, 10));
    assert!(bound_ok(true, Some((&d, 20)), Some(d), 10));
    assert!(!bound_ok(true, Some((&d, 20)), None, 10));
    assert!(!bound_ok(true, Some((&d, 20)), Some([8; 32]), 10));
    assert!(!bound_ok(true, Some((&d, 20)), Some(d), 20));
    assert!(!bound_ok(true, None, Some(d), 10));
    assert_eq!(split_cookie("abc.def"), ("abc", Some("def")));
    assert_eq!(split_cookie("abc"), ("abc", None));
}

#[test]
fn the_headers_name_the_realm_endpoints() {
    assert_eq!(
        registration("/realms/acme", "XYZ"),
        "(ES256);path=\"/realms/acme/v1/dbsc/register\";challenge=\"XYZ\""
    );
    assert_eq!(challenge("XYZ", "ses_1"), "\"XYZ\";id=\"ses_1\"");
    let c = session_config("ses_1", "https://acme.example", "");
    assert_eq!(c["refresh_url"], "/v1/dbsc/refresh");
    assert_eq!(c["credentials"][0]["name"], BOUND_COOKIE);
}
