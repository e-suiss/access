#![allow(clippy::unwrap_used, reason = "test")]

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;
use access_kernel::verify::key_scope::thumbprint;
use axum::http::{HeaderMap, HeaderValue, Method};
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};

use super::*;

const ORIGIN: &str = "https://access-server:9443";
const NOW: u64 = 1_800_000_000_000;

fn statement(domain: Digest, intent: Digest, mode: Mode, iat: u64) -> Vec<u8> {
    Statement {
        domain,
        nonce: vec![9; 16],
        intent,
        mode,
        pep: "access-console".to_owned(),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Public(Id([1; 16])),
        iat,
        exercise: None,
    }
    .to_bytes()
    .unwrap()
}

fn signed(signer: &SoftSigner, payload: &[u8]) -> Vec<u8> {
    sign_sign1(
        signer as &dyn Signer,
        thumbprint(&signer.public_key()),
        CONTENT_TYPE,
        payload,
    )
    .unwrap()
}

// TN-128, OP-151 m.3 (e): a read proof is a CT0 AIS by the session's Instance over this request
#[test]
fn read_proof_binds_instance_mode_domain_request_and_time() {
    let (key, _) = SoftSigner::generate_p256().unwrap();
    let (other, _) = SoftSigner::generate_p256().unwrap();
    let kid = thumbprint(&key.public_key());
    let pk = key.public_key();
    let domain = Digest([3; 32]);
    let target = "/admin/v1/realms/acme/clients?limit=10";
    let intent = read_intent(&Method::GET, target);
    let instance = Some((&kid, &pk));
    let ok = signed(&key, &statement(domain, intent, Mode::Check, NOW));
    assert!(verify_read_proof(&ok, instance, &domain, &intent, NOW).is_ok());
    assert_eq!(
        verify_read_proof(&ok, None, &domain, &intent, NOW),
        Err(ProofError::NoInstance)
    );
    let cases = [
        signed(&other, &statement(domain, intent, Mode::Check, NOW)),
        signed(&key, &statement(domain, intent, Mode::Commit, NOW)),
        signed(&key, &statement(Digest([4; 32]), intent, Mode::Check, NOW)),
        signed(
            &key,
            &statement(
                domain,
                read_intent(&Method::GET, "/admin/v1/realms/acme/clients"),
                Mode::Check,
                NOW,
            ),
        ),
        signed(&key, &statement(domain, intent, Mode::Check, NOW - 61_000)),
        signed(&key, &statement(domain, intent, Mode::Check, NOW + 61_000)),
        b"not an AIS".to_vec(),
    ];
    for bad in cases {
        assert_eq!(
            verify_read_proof(&bad, instance, &domain, &intent, NOW),
            Err(ProofError::Rejected)
        );
    }
}

// TN-131: state-changing requests name the configured origin; Host is never consulted
#[test]
fn origin_gate_uses_configuration_only() {
    let mut h = HeaderMap::new();
    assert_eq!(gate(&h, &Method::GET, ORIGIN), Gate::Pass);
    assert_eq!(gate(&h, &Method::POST, ORIGIN), Gate::Origin);
    h.insert("host", HeaderValue::from_static("access-server:9443"));
    assert_eq!(gate(&h, &Method::POST, ORIGIN), Gate::Origin);
    h.insert("origin", HeaderValue::from_static(ORIGIN));
    assert_eq!(gate(&h, &Method::POST, ORIGIN), Gate::Pass);
    h.insert("origin", HeaderValue::from_static("https://evil.example"));
    assert_eq!(gate(&h, &Method::DELETE, ORIGIN), Gate::Origin);
    let mut x = HeaderMap::new();
    x.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
    assert_eq!(gate(&x, &Method::GET, ORIGIN), Gate::CrossSite);
    x.insert("sec-fetch-site", HeaderValue::from_static("same-site"));
    assert_eq!(gate(&x, &Method::GET, ORIGIN), Gate::CrossSite);
    x.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    assert_eq!(gate(&x, &Method::GET, ORIGIN), Gate::Pass);
}

// TN-128: the ADP proxy reaches reads only; nothing it forwards is recorded or committed
#[test]
fn adp_proxy_reaches_reads_only() {
    for ok in [
        "explain",
        "search/grants",
        "search/acceptances",
        "eligibility:check",
    ] {
        assert!(adp_read(ok), "{ok}");
    }
    for bad in [
        "evaluation",
        "evaluations",
        "search/",
        "search/../evaluation",
        "search/Grants",
        "explain/x",
        "",
    ] {
        assert!(!adp_read(bad), "{bad}");
    }
}

// TN-131: the admin proxy names plain paths under /admin/v1 only
#[test]
fn admin_proxy_paths_are_plain() {
    assert!(admin_path("realms/acme/clients"));
    assert!(admin_path("platform"));
    for bad in [
        "",
        "realms//x",
        "../x",
        "realms/./x",
        "realms/%2e%2e",
        "a\\b",
        "a b",
    ] {
        assert!(!admin_path(bad), "{bad}");
    }
}

// TN-131: strict CSP, no referrer, isolation and minimal permissions on every answer
#[test]
fn security_headers_are_strict() {
    let mut h = HeaderMap::new();
    h.insert("content-security-policy", HeaderValue::from_static("x"));
    secure(&mut h);
    let csp = h["content-security-policy"].to_str().unwrap();
    for d in [
        "default-src 'none'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "require-trusted-types-for 'script'",
    ] {
        assert!(csp.contains(d), "{d}");
    }
    assert!(!csp.contains("unsafe-inline") && !csp.contains("'unsafe-eval'"));
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["cross-origin-opener-policy"], "same-origin");
    assert_eq!(h["cross-origin-embedder-policy"], "require-corp");
    assert!(
        h["permissions-policy"]
            .to_str()
            .unwrap()
            .contains("camera=()")
    );
}

// TN-128: credentials never cross the proxies
#[test]
fn proxies_pass_on_no_credentials() {
    for name in ["cookie", "authorization", "dpop", "host", "x-forwarded-for"] {
        assert!(!ADMIN_FORWARDED.contains(&name), "{name}");
        assert!(!ADP_FORWARDED.contains(&name), "{name}");
        assert!(!RETURNED.contains(&name), "{name}");
    }
    assert!(!RETURNED.contains(&"set-cookie"));
    assert!(ADMIN_FORWARDED.contains(&"x-access-ais"));
    assert!(!ADP_FORWARDED.contains(&"x-access-ais"));
}
