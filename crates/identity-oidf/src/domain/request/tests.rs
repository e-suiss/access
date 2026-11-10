use super::*;
use crate::statement::ENTITY_TYP;
use crate::testkit::{Entity, Fed, HOUR, LEAF, NOW};

const OP: &str = "https://op.example";

fn object(e: &Entity, extra: &str, exp_ms: u64) -> String {
    let payload = format!(
        r#"{{"iss":"{LEAF}","client_id":"{LEAF}","aud":"{OP}","exp":{}{extra}}}"#,
        exp_ms / 1000
    );
    e.key.sign("oauth-authz-req+jwt", &payload)
}

// IDP-19
#[test]
fn a_request_object_carries_jti_and_a_bounded_exp() {
    let leaf = Entity::new(LEAF);
    let keys = leaf.key.keys();
    let exp = NOW.saturating_add(600_000);
    let ok = object(&leaf, r#","jti":"j-1""#, exp);
    let r = verify_request_object(&ok, &keys, LEAF, OP, NOW).unwrap();
    assert_eq!((r.jti.as_str(), r.exp_ms), ("j-1", exp / 1000 * 1000));
    assert_eq!(
        verify_request_object(&object(&leaf, "", exp), &keys, LEAF, OP, NOW),
        Err(OidfError::Claims)
    );
    let long = format!(r#","jti":"{}""#, "j".repeat(MAX_JTI.saturating_add(1)));
    assert_eq!(
        verify_request_object(&object(&leaf, &long, exp), &keys, LEAF, OP, NOW),
        Err(OidfError::Claims)
    );
    let far = NOW.saturating_add(2 * HOUR);
    assert_eq!(
        verify_request_object(&object(&leaf, r#","jti":"j""#, far), &keys, LEAF, OP, NOW),
        Err(OidfError::Time)
    );
    assert_eq!(
        verify_request_object(&ok, &keys, LEAF, "https://other-op.example", NOW),
        Err(OidfError::Audience)
    );
    assert_eq!(
        verify_request_object(&ok, &keys, "https://other.example", OP, NOW),
        Err(OidfError::Claims)
    );
    assert_eq!(
        verify_request_object(&ok, &keys, LEAF, OP, exp.saturating_add(SKEW_MS)),
        Err(OidfError::Time)
    );
}

// IDP-19
#[test]
fn the_trust_chain_header_is_read_and_bounded() {
    let f = Fed::new();
    let chain = f.chain();
    let list = chain
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(",");
    let header = format!(
        r#"{{"alg":"ES256","kid":"{}","typ":"oauth-authz-req+jwt","trust_chain":[{list}]}}"#,
        f.leaf.key.kid
    );
    let payload = format!(
        r#"{{"iss":"{LEAF}","aud":"{OP}","jti":"j","exp":{}}}"#,
        NOW.saturating_add(600_000) / 1000
    );
    let ro = f.leaf.key.sign_header(&header, &payload);
    assert_eq!(trust_chain_header(&ro), Some(chain));
    assert!(verify_request_object(&ro, &f.leaf.key.keys(), LEAF, OP, NOW).is_ok());
    assert_eq!(trust_chain_header(&object(&f.leaf, "", NOW)), None);
}

// IDP-19
#[test]
fn explicit_registration_names_the_op() {
    let leaf = Entity::new(LEAF);
    let payload = format!(
        r#"{{"iss":"{LEAF}","sub":"{LEAF}","aud":"{OP}","iat":{},"exp":{},"jwks":{},"authority_hints":["https://int.example"]}}"#,
        NOW / 1000,
        NOW.saturating_add(HOUR) / 1000,
        access_crypto::jose::output::to_string(&leaf.key.jwks())
    );
    let body = leaf.key.sign(ENTITY_TYP, &payload);
    let (s, chain) = verify_explicit_registration(&body, OP, NOW).unwrap();
    assert_eq!(s.sub, LEAF);
    assert!(chain.is_none());
    assert_eq!(
        verify_explicit_registration(&body, "https://other-op.example", NOW),
        Err(OidfError::Audience)
    );
    let unaddressed = leaf.config(
        &["https://int.example"],
        &crate::testkit::rp_metadata(),
        &[],
    );
    assert_eq!(
        verify_explicit_registration(&unaddressed, OP, NOW),
        Err(OidfError::Audience)
    );
}
