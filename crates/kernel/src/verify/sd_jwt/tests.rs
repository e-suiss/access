use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ed25519_dalek::Signer as _;

use super::*;
use crate::verify::PureBackend;

const TYP: &str = "access-pap+sd-jwt";

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

fn disclosure(json: &str) -> String {
    b64url_encode(json.as_bytes())
}

fn issuer_jwt(payload: &str) -> String {
    let header = format!(
        r#"{{"alg":"Ed25519","kid":"{}","typ":"{TYP}"}}"#,
        b64url_encode(&[1; 32])
    );
    sign(&issuer_key(), &header, payload)
}

fn rules() -> Rules<'static> {
    Rules {
        typ: TYP,
        audience: "pep:shop",
        nonce: "n-1",
        now: 1_000_000,
        skew_ms: 60_000,
    }
}

fn kb_jwt(prefix: &str, aud: &str, nonce: &str, iat: i64) -> String {
    let sd_hash = b64url_encode(&Sha256::digest(prefix.as_bytes()));
    let payload =
        format!(r#"{{"iat":{iat},"aud":"{aud}","nonce":"{nonce}","sd_hash":"{sd_hash}"}}"#);
    sign(
        &holder_key(),
        r#"{"alg":"Ed25519","typ":"kb+jwt"}"#,
        &payload,
    )
}

fn cnf() -> String {
    format!(
        r#""cnf":{{"jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"}}}}"#,
        b64url_encode(&holder_key().verifying_key().to_bytes())
    )
}

struct Built {
    jwt: String,
    disclosures: Vec<String>,
}

fn build(holder: bool) -> Built {
    let given = disclosure(r#"["s1","given_name","Ada"]"#);
    let region = disclosure(r#"["s2","region","eu"]"#);
    let role = disclosure(r#"["s3","admin"]"#);
    let decoy = digest_of("decoy");
    let payload = format!(
        r#"{{"iss":"https://access.example","_sd_alg":"sha-256","_sd":["{}","{decoy}"],"address":{{"_sd":["{}"]}},"roles":["staff",{{"...":"{}"}}]{}}}"#,
        digest_of(&given),
        digest_of(&region),
        digest_of(&role),
        if holder {
            format!(",{}", cnf())
        } else {
            String::new()
        },
    );
    Built {
        jwt: issuer_jwt(&payload),
        disclosures: alloc::vec![given, region, role],
    }
}

fn present(b: &Built, which: &[usize]) -> String {
    let mut s = b.jwt.clone();
    for i in which {
        s.push('~');
        s.push_str(&b.disclosures[*i]);
    }
    s.push('~');
    s
}

fn run(p: &str) -> Result<Verified, SdJwtError> {
    verify(&PureBackend, p, &keys(), &rules(), Origin::Native)
}

// RFC 9901, CR-55 m.7
#[test]
fn selective_disclosure_applies_only_presented_claims() {
    let b = build(false);
    let v = run(&present(&b, &[0, 1, 2])).unwrap();
    assert!(!v.holder_bound);
    assert_eq!(
        v.claims.get("given_name").and_then(Json::as_str),
        Some("Ada")
    );
    assert_eq!(
        v.claims
            .get("address")
            .and_then(|a| a.get("region"))
            .and_then(Json::as_str),
        Some("eu")
    );
    assert_eq!(
        v.claims.get("roles"),
        Some(&Json::Array(alloc::vec![
            Json::Str("staff".to_string()),
            Json::Str("admin".to_string())
        ]))
    );
    assert!(v.claims.get("_sd").is_none() && v.claims.get("_sd_alg").is_none());

    let partial = run(&present(&b, &[1])).unwrap();
    assert!(partial.claims.get("given_name").is_none());
    assert_eq!(
        partial.claims.get("roles"),
        Some(&Json::Array(alloc::vec![Json::Str("staff".to_string())]))
    );
}

#[test]
fn disclosure_rules() {
    let b = build(false);
    assert_eq!(
        run(&present(&b, &[0, 0])).map(|_| ()),
        Err(SdJwtError::Duplicate)
    );
    let stray = format!("{}~{}~", b.jwt, disclosure(r#"["s9","extra","x"]"#));
    assert_eq!(run(&stray).map(|_| ()), Err(SdJwtError::Unreferenced));
    let bad = format!("{}~{}~", b.jwt, disclosure(r#"["s9","_sd","x"]"#));
    assert_eq!(run(&bad).map(|_| ()), Err(SdJwtError::Disclosure));
    let not_array = format!("{}~{}~", b.jwt, disclosure(r#"{"a":1}"#));
    assert_eq!(run(&not_array).map(|_| ()), Err(SdJwtError::Disclosure));
    assert_eq!(run(&b.jwt).map(|_| ()), Err(SdJwtError::Format));

    let collide = disclosure(r#"["s1","iss","https://evil"]"#);
    let jwt = issuer_jwt(&format!(
        r#"{{"iss":"https://access.example","_sd":["{}"]}}"#,
        digest_of(&collide)
    ));
    assert_eq!(
        run(&format!("{jwt}~{collide}~")).map(|_| ()),
        Err(SdJwtError::Collision)
    );

    let sha512 = issuer_jwt(r#"{"iss":"https://access.example","_sd_alg":"sha-512"}"#);
    assert_eq!(
        run(&format!("{sha512}~")).map(|_| ()),
        Err(SdJwtError::HashAlgorithm)
    );

    let element_as_property = disclosure(r#"["s1","x"]"#);
    let jwt = issuer_jwt(&format!(
        r#"{{"_sd":["{}"]}}"#,
        digest_of(&element_as_property)
    ));
    assert_eq!(
        run(&format!("{jwt}~{element_as_property}~")).map(|_| ()),
        Err(SdJwtError::Disclosure)
    );
}

// CR-55 m.7: holder-bound artefacts need a key binding JWT
#[test]
fn key_binding_rules() {
    let b = build(true);
    let prefix = present(&b, &[0]);
    let ok = format!("{prefix}{}", kb_jwt(&prefix, "pep:shop", "n-1", 1_000));
    let v = run(&ok).unwrap();
    assert!(v.holder_bound);

    assert_eq!(run(&prefix).map(|_| ()), Err(SdJwtError::KeyBinding));
    let other_prefix = present(&b, &[0, 1]);
    let wrong_hash = format!(
        "{prefix}{}",
        kb_jwt(&other_prefix, "pep:shop", "n-1", 1_000)
    );
    assert_eq!(run(&wrong_hash).map(|_| ()), Err(SdJwtError::KeyBinding));
    let wrong_nonce = format!("{prefix}{}", kb_jwt(&prefix, "pep:shop", "n-2", 1_000));
    assert_eq!(run(&wrong_nonce).map(|_| ()), Err(SdJwtError::KeyBinding));
    let wrong_aud = format!("{prefix}{}", kb_jwt(&prefix, "pep:bank", "n-1", 1_000));
    assert_eq!(
        run(&wrong_aud).map(|_| ()),
        Err(SdJwtError::Claims(ClaimError::Audience))
    );
    let old = format!("{prefix}{}", kb_jwt(&prefix, "pep:shop", "n-1", 939));
    assert_eq!(
        run(&old).map(|_| ()),
        Err(SdJwtError::Claims(ClaimError::Expired))
    );
    let future = format!("{prefix}{}", kb_jwt(&prefix, "pep:shop", "n-1", 1_061));
    assert_eq!(
        run(&future).map(|_| ()),
        Err(SdJwtError::Claims(ClaimError::NotYetValid))
    );

    let sd_hash = b64url_encode(&Sha256::digest(prefix.as_bytes()));
    let payload = format!(r#"{{"iat":1000,"aud":"pep:shop","nonce":"n-1","sd_hash":"{sd_hash}"}}"#);
    let input = format!(
        "{}.{}",
        b64url_encode(br#"{"alg":"Ed25519","typ":"kb+jwt"}"#),
        b64url_encode(payload.as_bytes())
    );
    let forged = format!(
        "{input}.{}",
        b64url_encode(&issuer_key().sign(input.as_bytes()).to_bytes())
    );
    assert_eq!(
        run(&format!("{prefix}{forged}")).map(|_| ()),
        Err(SdJwtError::Jws(JwsError::Signature(
            crate::verify::SignatureError::Invalid
        )))
    );
    let wrong_typ = sign(&holder_key(), r#"{"alg":"Ed25519","typ":"jwt"}"#, &payload);
    assert_eq!(
        run(&format!("{prefix}{wrong_typ}")).map(|_| ()),
        Err(SdJwtError::Jws(JwsError::Type))
    );

    let unbound = build(false);
    let p = present(&unbound, &[0]);
    let unexpected = format!("{p}{}", kb_jwt(&p, "pep:shop", "n-1", 1_000));
    assert_eq!(run(&unexpected).map(|_| ()), Err(SdJwtError::KeyBinding));
}

#[derive(serde::Deserialize)]
struct Rfc9901 {
    cases: Vec<Rfc9901Case>,
}

#[derive(serde::Deserialize)]
struct Rfc9901Case {
    digest: String,
    disclosure: String,
    name: Option<String>,
    value: String,
}

// RFC 9901 interop: digests and disclosure parsing match every example of the RFC
#[test]
fn rfc9901_disclosure_examples() {
    let v: Rfc9901 = serde_json::from_str(include_str!(
        "../../../../../conformance/vectors/external/rfc9901-disclosures.json"
    ))
    .unwrap();
    let (mut parsed, mut floats) = (0, 0);
    for c in &v.cases {
        assert_eq!(digest_of(&c.disclosure), c.digest);
        match parse_disclosure(&c.disclosure) {
            Ok(d) => {
                let expected = json::parse(c.value.as_bytes(), 4096).unwrap();
                let (name, value) = match d {
                    Disclosed::Property(name, value) => (Some(name), value),
                    Disclosed::Element(value) => (None, value),
                };
                assert_eq!(
                    (name, value),
                    (c.name.clone(), expected),
                    "{}",
                    c.disclosure
                );
                parsed += 1;
            }
            Err(SdJwtError::Json(JsonError::Number)) => floats += 1,
            Err(e) => panic!("{}: {e}", c.disclosure),
        }
    }
    assert_eq!(parsed + floats, v.cases.len());
    assert!(
        parsed > 80,
        "{parsed} parsed, {floats} with non-integer numbers"
    );
}
