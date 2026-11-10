//! RFC 9421 request signatures at a resource server (FAPI 2.0 Message Signing, OP-155 m.3 (k)):
//! signed with a P-256 key made at run time, verified by the SDK.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::format_push_string,
    reason = "test code"
)]

use access_sdk::resource::http_sig::{HttpSigError, SigKey, SigRules, SignedRequest, verify};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::{Signer as _, SoftSigner};

const NOW_S: u64 = 1_800_000_000;
const REQUIRED: [&str; 4] = ["@method", "@target-uri", "authorization", "content-digest"];

fn b64_std(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let v = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= n {
                out.push(char::from(A[((v >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

const HEADERS: [(&str, &str); 3] = [
    ("Authorization", "DPoP token-value"),
    (
        "Content-Digest",
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    ),
    ("Content-Type", "application/json"),
];

fn request<'a>(headers: &'a [(&'a str, &'a str)]) -> SignedRequest<'a> {
    SignedRequest {
        method: "POST",
        target_uri: "https://rs.example/payments?x=1",
        authority: "rs.example",
        path: "/payments",
        query: "?x=1",
        headers,
    }
}

fn rules(now_s: u64) -> SigRules<'static> {
    SigRules {
        required: &REQUIRED,
        now_ms: now_s * 1000,
        max_age_ms: 60_000,
        skew_ms: 5_000,
        keyid: Some("client-1"),
    }
}

fn sign(signer: &SoftSigner, params: &str, base_lines: &[(&str, &str)]) -> String {
    let mut base = String::new();
    for (k, v) in base_lines {
        base.push_str(&format!("\"{k}\": {v}\n"));
    }
    base.push_str(&format!("\"@signature-params\": {params}"));
    format!("sig1=:{}:", b64_std(&signer.sign(base.as_bytes()).unwrap()))
}

fn key(signer: &SoftSigner) -> SigKey {
    match signer.public_key() {
        PublicKey::P256(sec1) => SigKey::P256(sec1),
        other => panic!("{other:?}"),
    }
}

fn covered() -> Vec<(&'static str, &'static str)> {
    vec![
        ("@method", "POST"),
        ("@target-uri", "https://rs.example/payments?x=1"),
        ("authorization", "DPoP token-value"),
        ("content-digest", HEADERS[1].1),
    ]
}

const PARAMS: &str = r#"("@method" "@target-uri" "authorization" "content-digest");created=1800000000;keyid="client-1";alg="ecdsa-p256-sha256""#;

// OP-155 m.3 (k), RFC 9421 §3.2
#[test]
fn a_signed_request_verifies() {
    let signer = SoftSigner::generate_p256().unwrap().0;
    let sig = sign(&signer, PARAMS, &covered());
    let v = verify(
        &request(&HEADERS),
        &format!("sig1={PARAMS}"),
        &sig,
        &key(&signer),
        &rules(NOW_S + 10),
    )
    .unwrap();
    assert_eq!(v.label, "sig1");
    assert_eq!(v.components.len(), 4);
}

// OP-155 m.3 (k), TI-9
#[test]
fn anything_else_is_refused() {
    let signer = SoftSigner::generate_p256().unwrap().0;
    let sig = sign(&signer, PARAMS, &covered());
    let input = format!("sig1={PARAMS}");
    let k = key(&signer);
    let tampered = [HEADERS[0], ("Content-Digest", "sha-256=:AAAA:"), HEADERS[2]];
    assert_eq!(
        verify(&request(&tampered), &input, &sig, &k, &rules(NOW_S)),
        Err(HttpSigError::Signature)
    );
    assert_eq!(
        verify(&request(&HEADERS), &input, &sig, &k, &rules(NOW_S + 3600)),
        Err(HttpSigError::Time)
    );
    let partial =
        r#"("@method" "@target-uri" "authorization");created=1800000000;keyid="client-1""#;
    let sig2 = sign(&signer, partial, &covered()[..3]);
    assert_eq!(
        verify(
            &request(&HEADERS),
            &format!("sig1={partial}"),
            &sig2,
            &k,
            &rules(NOW_S)
        ),
        Err(HttpSigError::Components)
    );
    for alg in ["rsa-v1_5-sha256", "hmac-sha256", "rsa-pss-sha512"] {
        let p = PARAMS.replace("ecdsa-p256-sha256", alg);
        let s = sign(&signer, &p, &covered());
        assert_eq!(
            verify(
                &request(&HEADERS),
                &format!("sig1={p}"),
                &s,
                &k,
                &rules(NOW_S)
            ),
            Err(HttpSigError::Key),
            "{alg}"
        );
    }
    let other = SoftSigner::generate_p256().unwrap().0;
    assert_eq!(
        verify(
            &request(&HEADERS),
            &input,
            &sig,
            &key(&other),
            &rules(NOW_S)
        ),
        Err(HttpSigError::Signature)
    );
    let mut wrong_id = rules(NOW_S);
    wrong_id.keyid = Some("client-2");
    assert_eq!(
        verify(&request(&HEADERS), &input, &sig, &k, &wrong_id),
        Err(HttpSigError::Key)
    );
    assert_eq!(
        verify(&request(&HEADERS), "sig1=garbage", &sig, &k, &rules(NOW_S)),
        Err(HttpSigError::Malformed)
    );
}
