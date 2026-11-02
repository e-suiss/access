use alloc::format;
use alloc::string::String;

use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::verify::PureBackend;
use crate::verify::cose::{Algorithm, PublicKey};

const NOW: u64 = 1_000_000;
const RS: &str = "https://rs.example";
const ISSUER: &str = "https://as.example";

fn issuer_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn holder_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[8; 32])
}

fn keys() -> KeySet {
    let mut k = KeySet::default();
    k.insert(
        [1; 32],
        PublicKey::Ed25519(issuer_key().verifying_key().to_bytes()),
    )
    .unwrap();
    k.allowed.insert(Algorithm::Ed25519);
    k
}

fn sign(key: &ed25519_dalek::SigningKey, header: &str, payload: &str) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    format!(
        "{input}.{}",
        b64url_encode(&key.sign(input.as_bytes()).to_bytes())
    )
}

fn issued(typ: &str, payload: &str) -> String {
    let header = format!(
        r#"{{"alg":"Ed25519","kid":"{}","typ":"{typ}"}}"#,
        b64url_encode(&[1; 32])
    );
    sign(&issuer_key(), &header, payload)
}

fn domain() -> Digest {
    Digest([4; 32])
}

fn detail(kind: &str) -> String {
    format!(
        r#"{{"type":"shop/refund/v1","kind":"{kind}","domain":"{}","validity":{{}}}}"#,
        digest_text(&domain())
    )
}

fn at_payload(aud: &str, cnf: &str, details: &str) -> String {
    format!(
        r#"{{"iss":"{ISSUER}","sub":"p-1","aud":{aud},"exp":2000,"iat":900,"jti":"j-1","client_id":"c-1","cnf":{cnf},"authorization_details":[{details}]}}"#
    )
}

fn jkt() -> Confirmation {
    Confirmation::Jkt([5; 32])
}

fn jkt_json() -> String {
    format!(r#"{{"jkt":"{}"}}"#, b64url_encode(&[5; 32]))
}

fn run(token: &str, confirmation: &Confirmation) -> Result<AccessToken, ProjectionError> {
    verify_access_token(
        &PureBackend,
        token,
        &keys(),
        &AccessTokenRules {
            issuer: ISSUER,
            audience: RS,
            domain: &domain(),
            confirmation,
            now: NOW,
            skew_ms: 60_000,
        },
    )
}

fn at(aud: &str, cnf: &str, details: &str) -> String {
    issued(ACCESS_TOKEN_TYP, &at_payload(aud, cnf, details))
}

// L0-ENC-20
#[test]
fn digest_text_is_tagged() {
    assert_eq!(
        digest_text(&Digest([0; 32])),
        "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
}

// §9.9, RFC 9068, §9.13.5
#[test]
fn a_bound_token_of_one_kind_verifies() {
    let aud = format!("\"{RS}\"");
    let t = run(&at(&aud, &jkt_json(), &detail("intent")), &jkt()).unwrap();
    assert_eq!(t.kind, Kind::Intent);
    let both = format!("{},{}", detail("bounds"), detail("bounds"));
    let t = run(&at(&aud, &jkt_json(), &both), &jkt()).unwrap();
    assert_eq!(t.kind, Kind::Bounds);
    let mtls = Confirmation::X5tS256([6; 32]);
    let cnf = format!(r#"{{"x5t#S256":"{}"}}"#, b64url_encode(&[6; 32]));
    assert!(run(&at(&aud, &cnf, &detail("bounds")), &mtls).is_ok());
}

// §9.9.3 rule 1, RFC 8707: one audience only
#[test]
fn an_audience_array_is_rejected() {
    let aud = format!("[\"{RS}\"]");
    assert_eq!(
        run(&at(&aud, &jkt_json(), &detail("intent")), &jkt()),
        Err(ProjectionError::Claims(ClaimError::Audience))
    );
    assert_eq!(
        run(&at("\"other\"", &jkt_json(), &detail("intent")), &jkt()),
        Err(ProjectionError::Claims(ClaimError::Audience))
    );
}

// §9.9.3 rule 2, PI-11: no bearer token, and only the presented key
#[test]
fn confirmation_is_required_and_matched() {
    let aud = format!("\"{RS}\"");
    let other = format!(r#"{{"jkt":"{}"}}"#, b64url_encode(&[9; 32]));
    let two = format!(
        r#"{{"jkt":"{0}","x5t#S256":"{0}"}}"#,
        b64url_encode(&[5; 32])
    );
    let jwk = r#"{"jwk":{"kty":"OKP"}}"#;
    for (cnf, want) in [
        ("{}", ProjectionError::Confirmation),
        (other.as_str(), ProjectionError::Confirmation),
        (two.as_str(), ProjectionError::Confirmation),
        (jwk, ProjectionError::Confirmation),
        ("\"x\"", ProjectionError::Member("cnf")),
    ] {
        assert_eq!(
            run(&at(&aud, cnf, &detail("intent")), &jkt()),
            Err(want),
            "{cnf}"
        );
    }
    let mtls = Confirmation::X5tS256([5; 32]);
    assert_eq!(
        run(&at(&aud, &jkt_json(), &detail("intent")), &mtls),
        Err(ProjectionError::Confirmation)
    );
    let payload = format!(
        r#"{{"iss":"{ISSUER}","sub":"p","aud":"{RS}","exp":2000,"iat":900,"jti":"j","client_id":"c","authorization_details":[{}]}}"#,
        detail("intent")
    );
    assert_eq!(
        run(&issued(ACCESS_TOKEN_TYP, &payload), &jkt()),
        Err(ProjectionError::Member("cnf"))
    );
}

// §9.9.3 rule 3, §9.13.5: authority only in RAR, one kind, one intent, this domain
#[test]
fn authority_details_are_checked() {
    let aud = format!("\"{RS}\"");
    let mixed = format!("{},{}", detail("intent"), detail("bounds"));
    let two = format!("{},{}", detail("intent"), detail("intent"));
    let other = r#"{"type":"t","kind":"bounds","domain":"sha-256:x","validity":{}}"#;
    let unknown = detail("scope");
    let untyped = r#"{"kind":"bounds"}"#;
    let no_validity = format!(
        r#"{{"type":"t","kind":"bounds","domain":"{}"}}"#,
        digest_text(&domain())
    );
    for (details, want) in [
        ("", ProjectionError::Authority),
        (mixed.as_str(), ProjectionError::Authority),
        (two.as_str(), ProjectionError::Authority),
        (other, ProjectionError::Domain),
        (unknown.as_str(), ProjectionError::Authority),
        (untyped, ProjectionError::Member("type")),
        (no_validity.as_str(), ProjectionError::Member("validity")),
        ("1", ProjectionError::Authority),
    ] {
        assert_eq!(
            run(&at(&aud, &jkt_json(), details), &jkt()),
            Err(want),
            "{details}"
        );
    }
}

// RFC 9068 §2.2: sub, iat, jti and client_id are required
#[test]
fn required_claims_are_checked() {
    let full = at_payload(&format!("\"{RS}\""), &jkt_json(), &detail("intent"));
    for name in ["sub", "iat", "jti", "client_id"] {
        let payload = full.replace(&format!("\"{name}\":"), "\"x-removed\":");
        assert_eq!(
            run(&issued(ACCESS_TOKEN_TYP, &payload), &jkt()),
            Err(ProjectionError::Member(name)),
            "{name}"
        );
    }
    let expired = full.replace("\"exp\":2000", "\"exp\":900");
    assert_eq!(
        run(&issued(ACCESS_TOKEN_TYP, &expired), &jkt()),
        Err(ProjectionError::Claims(ClaimError::Expired))
    );
}

// CR-56 row 16: another artefact's typ is not an access token
#[test]
fn another_typ_is_rejected() {
    let payload = at_payload(&format!("\"{RS}\""), &jkt_json(), &detail("intent"));
    assert_eq!(
        run(&issued("access-receipt+jwt", &payload), &jkt()),
        Err(ProjectionError::Jws(JwsError::Type))
    );
}

fn pap_payload(iss: &str, extra: &str) -> String {
    format!(
        r#"{{"iss":"{iss}","iat":900,"exp":2000,"_sd_alg":"sha-256","projection_exercise":"e","holder":{{}},"capacity":"own","bounds":{{}},"validity":{{}},"lineage_commitment":"l"{extra}}}"#
    )
}

fn cnf() -> String {
    format!(
        r#","cnf":{{"jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"}}}}"#,
        b64url_encode(&holder_key().verifying_key().to_bytes())
    )
}

fn kb(prefix: &str) -> String {
    let sd_hash = b64url_encode(&Sha256::digest(prefix.as_bytes()));
    let payload = format!(r#"{{"iat":1000,"aud":"pep:shop","nonce":"n-1","sd_hash":"{sd_hash}"}}"#);
    sign(
        &holder_key(),
        r#"{"alg":"Ed25519","typ":"kb+jwt"}"#,
        &payload,
    )
}

fn run_pap(presentation: &str) -> Result<sd_jwt::Verified, ProjectionError> {
    verify_pap_sd_jwt(
        &PureBackend,
        presentation,
        &keys(),
        &sd_jwt::Rules {
            typ: "ignored",
            audience: "pep:shop",
            nonce: "n-1",
            now: NOW,
            skew_ms: 60_000,
        },
        &domain(),
    )
}

fn bound(payload: &str) -> String {
    let prefix = format!("{}~", issued(PAP_TYP, payload));
    format!("{prefix}{}", kb(&prefix))
}

// OP-143 m.6 (a), L0-SIG-50…52
#[test]
fn a_holder_bound_pap_of_this_domain_verifies() {
    let iss = digest_text(&domain());
    let v = run_pap(&bound(&pap_payload(&iss, &cnf()))).unwrap();
    assert!(v.holder_bound);
    assert_eq!(v.claims.get("capacity").and_then(Json::as_str), Some("own"));
}

// §9.10 step 1, step 3
#[test]
fn pap_profile_is_checked() {
    let iss = digest_text(&domain());
    let unbound = format!("{}~", issued(PAP_TYP, &pap_payload(&iss, "")));
    assert_eq!(run_pap(&unbound), Err(ProjectionError::Holder));
    assert_eq!(
        run_pap(&bound(&pap_payload("sha-256:other", &cnf()))),
        Err(ProjectionError::Domain)
    );
    let no_bounds = pap_payload(&iss, &cnf()).replace("\"bounds\":{}", "\"bounds\":1");
    assert_eq!(
        run_pap(&bound(&no_bounds)),
        Err(ProjectionError::Member("bounds"))
    );
    let wrong_typ = {
        let prefix = format!("{}~", issued("at+jwt", &pap_payload(&iss, &cnf())));
        format!("{prefix}{}", kb(&prefix))
    };
    assert_eq!(
        run_pap(&wrong_typ),
        Err(ProjectionError::SdJwt(SdJwtError::Jws(JwsError::Type)))
    );
}
