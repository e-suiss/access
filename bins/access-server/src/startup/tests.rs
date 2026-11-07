#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use super::*;
use crate::config::Suiss;

fn config(issuer: &str, management: &str) -> Config {
    Config {
        issuer: Some(issuer.to_owned()),
        suiss: Some(Suiss {
            region: "eu-central".to_owned(),
            relay: "https://relay.example".to_owned(),
            management_api: management.to_owned(),
            products: BTreeMap::new(),
            platform_realm: None,
        }),
        ..Config::default()
    }
}

fn cert(names: &[&str]) -> Vec<u8> {
    let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    let params = rcgen::CertificateParams::new(names).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().pem().into_bytes()
}

// OP-148, §17.9.6: the certificate covers the issuer and the management origin, or the server
// does not start
#[test]
fn the_certificate_must_cover_both_origins() {
    let c = config("https://access.example", "https://api.access.example:9443");
    let both = cert(&["access.example", "api.access.example"]);
    assert_eq!(tls_names(&c, &both), Ok(()));
    let wildcard = cert(&["access.example", "*.access.example"]);
    assert_eq!(tls_names(&c, &wildcard), Ok(()));
    let issuer_only = cert(&["access.example"]);
    let e = tls_names(&c, &issuer_only).unwrap_err();
    assert!(e.contains("api.access.example"), "{e}");
    let other = cert(&["elsewhere.example"]);
    assert!(
        tls_names(&c, &other)
            .unwrap_err()
            .contains("access.example")
    );
    assert!(tls_names(&c, b"not a certificate").is_err());
}

// L1-ADP-11, OP-148: an issuer or a management origin out of its one form fails the check
#[test]
fn origins_are_in_their_one_form() {
    let names = cert(&["access.example"]);
    for (issuer, management) in [
        ("http://access.example", "https://access.example"),
        ("https://access.example/", "https://access.example"),
    ] {
        assert!(
            tls_names(&config(issuer, management), &names).is_err(),
            "{issuer} {management}"
        );
    }
    assert_eq!(
        origins(&config(
            "https://access.example",
            "https://access.example:9443"
        ))
        .unwrap(),
        ["access.example"]
    );
}

// MD-8, OP-148: one failed check fails the report; the report names every check
#[test]
fn any_failed_check_refuses_to_serve() {
    let mut ok = Report::default();
    ok.record("listeners", Ok(()));
    ok.record("tls-names", Ok(()));
    assert!(ok.passed());
    assert_eq!(ok.clone().into_result(), Ok(()));
    let mut bad = ok;
    bad.record("authority-signer", Err("down".to_owned()));
    bad.record("realm-jwks", Ok(()));
    assert!(!bad.passed());
    assert_eq!(bad.failed(), ["authority-signer"]);
    let e = bad.into_result().unwrap_err();
    assert!(e.contains("authority-signer"), "{e}");
}

// OP-148, CMP-22b: a configured authority signer that does not answer fails; none configured
// passes (receipts are then not signed, OP-143 m.5)
#[tokio::test]
async fn an_unreachable_signer_fails_the_start() {
    assert_eq!(authority_signer(None).await, Ok(()));
    let missing = std::env::temp_dir().join(format!("no-signer-{}.sock", std::process::id()));
    assert!(authority_signer(Some(&missing)).await.is_err());
}

// OP-138, §17.9.7: the identity plane's failures land on their own check
#[test]
fn identity_failures_name_their_check() {
    let cases: [(Result<usize, StartupError>, &[&str]); 4] = [
        (Ok(2), &[]),
        (
            Err(StartupError::Signer),
            &["identity-signer", "realm-issuers", "realm-jwks"],
        ),
        (
            Err(StartupError::Issuer("acme".to_owned())),
            &["realm-issuers", "realm-jwks"],
        ),
        (Err(StartupError::Jwks("acme".to_owned())), &["realm-jwks"]),
    ];
    for (outcome, failed) in cases {
        let mut r = Report::default();
        identity(&outcome, &mut r);
        assert_eq!(r.failed(), failed);
    }
}

// OP-148, §17.9.6: the admin interface is never on the public listener
#[test]
fn a_shared_admin_listener_fails_the_start() {
    let mut c = config("https://access.example", "https://access.example:9443");
    c.management_listen = Some(c.listen);
    c.internal_listen = Some("127.0.0.1:9090".parse().unwrap());
    assert!(crate::config::check_listeners(&c).is_err());
}
