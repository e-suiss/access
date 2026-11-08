extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;
use crate::verify::PureBackend;

const NOW: u64 = 1_800_000_000_000;
const URI: &str = "https://login.example.com/token";
const TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";

fn ed_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
}

fn p_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap()
}

fn ed_jwk() -> String {
    format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
        b64url_encode(&ed_key().verifying_key().to_bytes())
    )
}

fn p_point() -> Vec<u8> {
    p_key()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec()
}

fn p_jwk() -> String {
    let point = p_point();
    format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
        b64url_encode(&point[1..33]),
        b64url_encode(&point[33..])
    )
}

fn sign_ed(m: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    ed_key().sign(m).to_bytes().to_vec()
}

fn sign_p(m: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer as _;
    let s: p256::ecdsa::Signature = p_key().sign(m);
    s.to_bytes().to_vec()
}

fn compact(header: &str, payload: &str, sign: &dyn Fn(&[u8]) -> Vec<u8>) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(&sig))
}

fn ed_header() -> String {
    format!(r#"{{"typ":"dpop+jwt","alg":"Ed25519","jwk":{}}}"#, ed_jwk())
}

fn payload(extra: &str) -> String {
    format!(
        r#"{{"jti":"j-1","htm":"POST","htu":"{URI}","iat":{}{extra}}}"#,
        NOW / 1000
    )
}

fn proof(extra: &str) -> String {
    compact(&ed_header(), &payload(extra), &sign_ed)
}

fn allowed() -> BTreeSet<Algorithm> {
    [Algorithm::Es256, Algorithm::Ed25519].into_iter().collect()
}

fn check(proof: &str, edit: &dyn Fn(&mut ProofRules<'_>)) -> Result<Proof, DpopError> {
    let allowed = allowed();
    let mut rules = ProofRules {
        method: "POST",
        uri: URI,
        allowed: &allowed,
        now: NOW,
        lifetime_ms: 5_000,
        skew_ms: 5_000,
        access_token: None,
        bound_jkt: None,
    };
    edit(&mut rules);
    verify_proof(&PureBackend, proof, &rules)
}

fn same(_: &mut ProofRules<'_>) {}

// IDP-11, TN-28, MD-3: both allowed algorithms verify; the thumbprint is RFC 7638's
#[test]
fn valid_proofs_verify_with_both_algorithms() {
    let ed = check(&proof(r#","nonce":"n-1""#), &same).unwrap();
    assert_eq!(ed.algorithm, Algorithm::Ed25519);
    assert_eq!(ed.jkt, thumbprint(&ed.key));
    assert_eq!(ed.nonce.as_deref(), Some("n-1"));
    assert_eq!(ed.htu, URI);
    assert_eq!(ed.iat, NOW);
    let header = format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{}}}"#, p_jwk());
    let es = check(&compact(&header, &payload(""), &sign_p), &same).unwrap();
    assert_eq!(es.algorithm, Algorithm::Es256);
    assert_eq!(es.key, PublicKey::P256(p_point()));
    assert_eq!(es.nonce, None);
}

// IDP-11, TN-31: cnf.jkt and dpop_jkt text form
#[test]
fn jkt_text_round_trips() {
    let jkt = [0x5a; 32];
    assert_eq!(parse_jkt(&jkt_text(&jkt)), Ok(jkt));
    assert_eq!(parse_jkt("AAAA"), Err(DpopError::Jkt));
    assert_eq!(parse_jkt("not base64!"), Err(DpopError::Jkt));
}

// IDP-11 step 1, TN-28: shape and required claims
#[test]
fn step_1_shape_and_required_claims() {
    let p = proof("");
    let parts: Vec<&str> = p.split('.').collect();
    for bad in [
        String::from("a.b"),
        format!("{p}.x"),
        "x".repeat(MAX_PROOF + 1),
        format!("{}.{}.{}", parts[0], parts[1], "+++"),
    ] {
        assert_eq!(check(&bad, &same).unwrap_err().step(), Step::Shape, "{bad}");
    }
    for missing in ["jti", "htm", "htu", "iat"] {
        let mut members = Vec::new();
        for (k, v) in [
            ("jti", "\"j\"".to_string()),
            ("htm", "\"POST\"".to_string()),
            ("htu", format!("\"{URI}\"")),
            ("iat", (NOW / 1000).to_string()),
        ] {
            if k != missing {
                members.push(format!("\"{k}\":{v}"));
            }
        }
        let body = format!("{{{}}}", members.join(","));
        let err = check(&compact(&ed_header(), &body, &sign_ed), &same).unwrap_err();
        assert_eq!(err, DpopError::Claim(missing));
        assert_eq!(err.step(), Step::Shape);
    }
    let long = "j".repeat(MAX_JTI + 1);
    let body = format!(
        r#"{{"jti":"{long}","htm":"POST","htu":"{URI}","iat":{}}}"#,
        NOW / 1000
    );
    assert_eq!(
        check(&compact(&ed_header(), &body, &sign_ed), &same),
        Err(DpopError::Claim("jti"))
    );
    let extra = format!(
        r#"{{"typ":"dpop+jwt","alg":"Ed25519","jwk":{},"kid":"x"}}"#,
        ed_jwk()
    );
    assert_eq!(
        check(&compact(&extra, &payload(""), &sign_ed), &same),
        Err(DpopError::Header)
    );
}

// IDP-11 step 2, TN-28: typ is exactly dpop+jwt
#[test]
fn step_2_typ() {
    for typ in ["at+jwt", "JWT", "DPOP+JWT", "application/dpop+jwt"] {
        let header = format!(r#"{{"typ":"{typ}","alg":"Ed25519","jwk":{}}}"#, ed_jwk());
        let err = check(&compact(&header, &payload(""), &sign_ed), &same).unwrap_err();
        assert_eq!(err.step(), Step::Type, "{typ}");
    }
}

// IDP-11 step 3, MD-3, AG-38: EdDSA, symmetric, none and algorithms outside the allowlist fail
#[test]
fn step_3_algorithm_allowlist_rejects_eddsa() {
    for alg in ["EdDSA", "HS256", "none", "RS256", "ES384", "ML-DSA-65"] {
        let header = format!(r#"{{"typ":"dpop+jwt","alg":"{alg}","jwk":{}}}"#, ed_jwk());
        let err = check(&compact(&header, &payload(""), &sign_ed), &same).unwrap_err();
        assert_eq!(err, DpopError::Algorithm, "{alg}");
        assert_eq!(err.step(), Step::Algorithm);
    }
    let only_es: BTreeSet<Algorithm> = [Algorithm::Es256].into_iter().collect();
    let allowed = allowed();
    let rules = ProofRules {
        method: "POST",
        uri: URI,
        allowed: &only_es,
        now: NOW,
        lifetime_ms: 5_000,
        skew_ms: 5_000,
        access_token: None,
        bound_jkt: None,
    };
    assert_eq!(
        verify_proof(&PureBackend, &proof(""), &rules),
        Err(DpopError::Algorithm)
    );
    let mismatch = format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{}}}"#, ed_jwk());
    assert_eq!(
        check(&compact(&mismatch, &payload(""), &sign_ed), &same),
        Err(DpopError::Algorithm)
    );
    assert!(allowed.contains(&Algorithm::Ed25519));
}

// IDP-11 step 4, TN-28: jwk is a public key of a supported type
#[test]
fn step_4_jwk_must_be_public() {
    let x = b64url_encode(&ed_key().verifying_key().to_bytes());
    let private = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","d":"AAAA"}}"#);
    let header = format!(r#"{{"typ":"dpop+jwt","alg":"Ed25519","jwk":{private}}}"#);
    let err = check(&compact(&header, &payload(""), &sign_ed), &same).unwrap_err();
    assert_eq!(err, DpopError::PrivateKey);
    assert_eq!(err.step(), Step::Jwk);
    for jwk in [
        r#"{"kty":"oct","k":"AAAA"}"#.to_string(),
        format!(r#"{{"kty":"OKP","crv":"X25519","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","y":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","x5c":"x"}}"#),
        r#"{"kty":"OKP","crv":"Ed25519","x":"AAAA"}"#.to_string(),
        format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
            b64url_encode(&[0; 32])
        ),
        format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            b64url_encode(&[1; 32]),
            b64url_encode(&[2; 32])
        ),
    ] {
        let header = format!(r#"{{"typ":"dpop+jwt","alg":"Ed25519","jwk":{jwk}}}"#);
        let err = check(&compact(&header, &payload(""), &sign_ed), &same).unwrap_err();
        assert_eq!(err.step(), Step::Jwk, "{jwk}");
    }
    let webcrypto =
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","ext":true,"key_ops":["verify"]}}"#);
    let header = format!(r#"{{"typ":"dpop+jwt","alg":"Ed25519","jwk":{webcrypto}}}"#);
    assert!(check(&compact(&header, &payload(""), &sign_ed), &same).is_ok());
}

// IDP-11 step 5, TN-28: the signature is checked with the header jwk
#[test]
fn step_5_signature() {
    let other = |m: &[u8]| {
        use ed25519_dalek::Signer as _;
        ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .sign(m)
            .to_bytes()
            .to_vec()
    };
    let err = check(&compact(&ed_header(), &payload(""), &other), &same).unwrap_err();
    assert_eq!(err.step(), Step::Signature);
    let p = proof("");
    let tampered = p.replacen(
        p.split('.').nth(1).unwrap(),
        &b64url_encode(payload(r#","x":1"#).as_bytes()),
        1,
    );
    assert_eq!(check(&tampered, &same).unwrap_err().step(), Step::Signature);
}

// IDP-11 step 6, TN-28: htm is compared exactly
#[test]
fn step_6_method() {
    for method in ["GET", "post", "PUT"] {
        let err = check(&proof(""), &|r| r.method = method).unwrap_err();
        assert_eq!(err, DpopError::Method, "{method}");
        assert_eq!(err.step(), Step::Method);
    }
}

// IDP-11 step 7, TN-28: htu is compared after RFC 3986 normalisation, without query and fragment
#[test]
fn step_7_uri_after_normalisation() {
    for request in [
        "https://login.example.com/token",
        "HTTPS://LOGIN.example.COM:443/token",
        "https://login.example.com/token?x=1#frag",
        "https://login.example.com/a/../token",
        "https://login.example.com/./token",
        "https://login.example.com/%74oken",
    ] {
        assert!(check(&proof(""), &|r| r.uri = request).is_ok(), "{request}");
    }
    for request in [
        "https://login.example.com/token/",
        "http://login.example.com/token",
        "https://login.example.com:8443/token",
        "https://other.example.com/token",
        "https://login.example.com/Token",
    ] {
        let err = check(&proof(""), &|r| r.uri = request).unwrap_err();
        assert_eq!(err, DpopError::Uri, "{request}");
        assert_eq!(err.step(), Step::Uri);
    }
    assert_eq!(
        check(&proof(""), &|r| r.uri = "ftp://x/"),
        Err(DpopError::Target)
    );
    let body = format!(
        r#"{{"jti":"j","htm":"POST","htu":"https://u@login.example.com/token","iat":{}}}"#,
        NOW / 1000
    );
    assert_eq!(
        check(&compact(&ed_header(), &body, &sign_ed), &same),
        Err(DpopError::Uri)
    );
}

// TN-28: RFC 3986 §6.2.2 and §6.2.3 normalisation cases
#[test]
fn htu_normalisation_cases() {
    let cases = [
        ("https://Example.COM", "https://example.com/"),
        ("https://example.com:443/", "https://example.com/"),
        ("http://example.com:80/a", "http://example.com/a"),
        ("http://example.com:/a", "http://example.com/a"),
        ("https://example.com:0443/a", "https://example.com/a"),
        ("https://example.com:8443/a", "https://example.com:8443/a"),
        ("https://example.com/a/b/../c", "https://example.com/a/c"),
        ("https://example.com/a/./b/.", "https://example.com/a/b/"),
        ("https://example.com/a/b/..", "https://example.com/a/"),
        ("https://example.com/../a", "https://example.com/a"),
        ("https://example.com/%7euser", "https://example.com/~user"),
        ("https://example.com/%2e%2E/a", "https://example.com/a"),
        ("https://example.com/a%2fb", "https://example.com/a%2Fb"),
        ("https://example.com/a?b#c", "https://example.com/a"),
        ("https://example.com#c", "https://example.com/"),
        ("https://[::1]:8443/a", "https://[::1]:8443/a"),
        ("https://[::1]/a", "https://[::1]/a"),
        ("https://example.com//a", "https://example.com//a"),
    ];
    for (input, expected) in cases {
        assert_eq!(normalize_htu(input).as_deref(), Some(expected), "{input}");
    }
    for bad in [
        "example.com/a",
        "ftp://example.com/a",
        "https://",
        "https://user@example.com/",
        "https://example.com:99999/",
        "https://example.com:8x/",
        "https://exa mple.com/",
        "https://example.com/a b",
        "https://example.com/%zz",
        "https://example.com/%4",
        "https://exämple.com/",
        "https://[zz]/",
    ] {
        assert_eq!(normalize_htu(bad), None, "{bad}");
    }
}

// IDP-11 step 8, TN-30: iat window is lifetime plus skew in the past and skew in the future
#[test]
fn step_8_iat_window() {
    let at = |seconds: u64| {
        let body = format!(r#"{{"jti":"j","htm":"POST","htu":"{URI}","iat":{seconds}}}"#);
        check(&compact(&ed_header(), &body, &sign_ed), &same)
    };
    let s = NOW / 1000;
    assert!(at(s + 5).is_ok());
    assert!(at(s - 10).is_ok());
    for t in [s + 6, s - 11, 0] {
        let err = at(t).unwrap_err();
        assert_eq!(err, DpopError::Iat, "{t}");
        assert_eq!(err.step(), Step::Iat);
    }
    let body = format!(r#"{{"jti":"j","htm":"POST","htu":"{URI}","iat":-1}}"#);
    assert_eq!(
        check(&compact(&ed_header(), &body, &sign_ed), &same),
        Err(DpopError::Iat)
    );
    let body = format!(r#"{{"jti":"j","htm":"POST","htu":"{URI}","iat":"{s}"}}"#);
    assert_eq!(
        check(&compact(&ed_header(), &body, &sign_ed), &same),
        Err(DpopError::Claim("iat"))
    );
}

// IDP-11 step 11, §10.4.3 m.5: at the resource server ath is the token hash
#[test]
fn step_11_ath() {
    let good = format!(r#","ath":"{}""#, ath(TOKEN));
    assert!(check(&proof(&good), &|r| r.access_token = Some(TOKEN)).is_ok());
    for extra in [String::new(), String::from(r#","ath":"AAAA""#)] {
        let err = check(&proof(&extra), &|r| r.access_token = Some(TOKEN)).unwrap_err();
        assert_eq!(err, DpopError::Ath);
        assert_eq!(err.step(), Step::Ath);
    }
    let other = format!(r#","ath":"{}""#, ath("other"));
    assert_eq!(
        check(&proof(&other), &|r| r.access_token = Some(TOKEN)),
        Err(DpopError::Ath)
    );
}

// IDP-11 step 12, TN-31: the key is the bound cnf.jkt or dpop_jkt
#[test]
fn step_12_bound_key() {
    let jkt = thumbprint(&PublicKey::Ed25519(ed_key().verifying_key().to_bytes()));
    let allowed = allowed();
    let mut rules = ProofRules {
        method: "POST",
        uri: URI,
        allowed: &allowed,
        now: NOW,
        lifetime_ms: 5_000,
        skew_ms: 5_000,
        access_token: None,
        bound_jkt: Some(&jkt),
    };
    assert!(verify_proof(&PureBackend, &proof(""), &rules).is_ok());
    rules.bound_jkt = Some(&[0; 32]);
    let err = verify_proof(&PureBackend, &proof(""), &rules).unwrap_err();
    assert_eq!(err, DpopError::Jkt);
    assert_eq!(err.step(), Step::Jkt);
}

// IDP-11: every stateless failure names one of the 12 steps and a stable code
#[test]
fn codes_are_distinct() {
    let all = [
        DpopError::Format,
        DpopError::Base64,
        DpopError::Json(JsonError::Size),
        DpopError::Header,
        DpopError::Claim("jti"),
        DpopError::Type,
        DpopError::Algorithm,
        DpopError::Jwk,
        DpopError::PrivateKey,
        DpopError::Signature(SignatureError::Invalid),
        DpopError::Method,
        DpopError::Uri,
        DpopError::Target,
        DpopError::Iat,
        DpopError::Ath,
        DpopError::Jkt,
    ];
    let codes: BTreeSet<&str> = all.iter().map(|e| e.code()).collect();
    assert_eq!(codes.len(), all.len());
}

// IDP-11 step 1: a proof of exactly the size limit is verified; the limit is checked first
#[test]
fn proof_size_limit_is_inclusive() {
    let sig_len = b64url_encode(&[0; 64]).len();
    let b64_len = |n: usize| (n * 4).div_ceil(3);
    let (header, body_bytes) = (0..MAX_HEADER)
        .find_map(|pad| {
            let header = format!("{}{}", ed_header(), " ".repeat(pad));
            let rest = MAX_PROOF - b64_len(header.len()) - sig_len - 2;
            let bytes = rest * 3 / 4;
            (b64_len(bytes) == rest && bytes <= MAX_PAYLOAD).then_some((header, bytes))
        })
        .unwrap();
    let base = payload("");
    let body = format!("{}{}", " ".repeat(body_bytes - base.len()), base);
    let p = compact(&header, &body, &sign_ed);
    assert_eq!(p.len(), MAX_PROOF);
    assert_eq!(check(&p, &same).map(|v| v.iat), Ok(NOW));
}

// TN-28: an htu is ASCII, at most MAX_URI long, and its port has at most five digits
#[test]
fn htu_bounds() {
    let at = format!("https://example.com/{}", "a".repeat(MAX_URI - 20));
    assert_eq!(at.len(), MAX_URI);
    assert_eq!(normalize_htu(&at).as_deref(), Some(at.as_str()));
    assert_eq!(normalize_htu(&format!("{at}a")), None);
    assert_eq!(normalize_htu("https://example.com/a?q=\u{e4}"), None);
    assert_eq!(normalize_htu("https://example.com:000443/"), None);
}
