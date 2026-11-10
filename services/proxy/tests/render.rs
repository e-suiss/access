//! IDP-30 (2), OP-156 m.3 (m): the committed engine configurations are what the one file
//! renders to. `ACCESS_UPDATE_GOLDEN=1` rewrites them.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::path::PathBuf;

use access_proxy::config::{Config, ConfigError};
use access_proxy::render::{TARGETS, Target, render};

fn golden() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn config() -> Config {
    Config::parse(&std::fs::read_to_string(golden().join("access-proxy.toml")).unwrap()).unwrap()
}

// IDP-30 (2), OP-156 m.3 (m)
#[test]
fn the_one_file_renders_to_the_committed_engine_configurations() {
    let c = config();
    for t in TARGETS {
        let text = render(&c, t).unwrap();
        let p = golden().join(t.file());
        if std::env::var_os("ACCESS_UPDATE_GOLDEN").is_some() {
            std::fs::write(&p, &text).unwrap();
            continue;
        }
        let committed = std::fs::read_to_string(&p).unwrap_or_default();
        assert_eq!(
            committed,
            text,
            "{} is stale; rerun with ACCESS_UPDATE_GOLDEN=1",
            p.display()
        );
    }
}

// IDP-30 (1), OP-156 m.15 (f)
#[test]
fn every_engine_asks_access_with_the_proxy_certificate_and_fails_closed() {
    let c = config();
    let envoy = render(&c, Target::Envoy).unwrap();
    assert!(envoy.contains("path_prefix: \"/proxy/v1/check/envoy\""));
    assert!(envoy.contains("failure_mode_allow: false"));
    assert!(envoy.contains("code: \"ServiceUnavailable\""));
    assert!(envoy.contains("tls_minimum_protocol_version: \"TLSv1_3\""));
    assert!(envoy.contains("filename: \"/etc/access-proxy/proxy.pem\""));
    let caddy = render(&c, Target::Caddy).unwrap();
    assert!(caddy.contains("uri /proxy/v1/check/caddy"));
    assert!(
        caddy.contains(
            "tls_client_auth /etc/access-proxy/proxy.pem /etc/access-proxy/proxy-key.pem"
        )
    );
    let traefik = render(&c, Target::Traefik).unwrap();
    assert!(
        traefik.contains("address: \"https://access.example.com:8443/proxy/v1/check/traefik\"")
    );
    assert!(traefik.contains("trustForwardHeader: false"));
    assert!(traefik.contains("cert: \"/etc/access-proxy/proxy.pem\""));
}

// IDP-30 (3), OP-156 m.3 (l)
#[test]
fn identity_headers_come_only_from_the_answer() {
    let c = config();
    let caddy = render(&c, Target::Caddy).unwrap();
    for h in ["Access-Identity", "X-Access-User", "X-Access-Email"] {
        assert_eq!(
            caddy.matches(&format!("request_header -{h}\n")).count(),
            2,
            "{h}"
        );
    }
    assert!(caddy.contains("copy_headers Access-Identity X-Access-User X-Access-Email\n"));
    assert!(caddy.contains("copy_headers Access-Identity\n"));
    let envoy = render(&c, Target::Envoy).unwrap();
    assert!(envoy.contains("- remove: \"access-identity\""));
    assert!(envoy.contains("- remove: \"x-access-user\""));
    assert_eq!(envoy.matches("request_headers_to_remove").count(), 1);
    let traefik = render(&c, Target::Traefik).unwrap();
    assert_eq!(traefik.matches("\"X-Access-User\": \"\"").count(), 2);
}

// OP-156 m.3 (m)
#[test]
fn envoy_and_traefik_need_the_listener_certificate() {
    let text = std::fs::read_to_string(golden().join("access-proxy.toml"))
        .unwrap()
        .replace("certificate = \"/etc/access-proxy/tls/apps.pem\"\n", "")
        .replace("key = \"/etc/access-proxy/tls/apps-key.pem\"\n", "");
    let c = Config::parse(&text).unwrap();
    assert!(matches!(
        render(&c, Target::Envoy),
        Err(ConfigError::Needs {
            engine: "envoy",
            ..
        })
    ));
    assert!(matches!(
        render(&c, Target::Traefik),
        Err(ConfigError::Needs {
            engine: "traefik",
            ..
        })
    ));
    let caddy = render(&c, Target::Caddy).unwrap();
    assert!(!caddy.contains("\ttls "));
    assert!(!caddy.contains("disable_redirects"));
}

// IDP-30 (2), OP-156 m.3 (m), Ek B 5360
#[test]
fn the_shared_behaviour_cases_cover_every_required_outcome() {
    use access_proxy::behaviour::{Phase, cases};
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/behaviour");
    let all = cases(&dir).unwrap();
    for (name, case) in &all {
        assert!(["wiki", "admin"].contains(&case.app.as_str()), "{name}");
        assert!(!case.expect.status.is_empty(), "{name}");
    }
    let has = |phase: Phase, f: &dyn Fn(&access_proxy::behaviour::Case) -> bool| {
        all.iter().any(|(_, k)| k.phase == phase && f(k))
    };
    assert!(has(Phase::Anonymous, &|k| k.expect.location.is_some()));
    assert!(has(Phase::SignedIn, &|k| k.expect.upstream && k.expect.identity));
    assert!(has(Phase::SignedIn, &|k| k.expect.status == [403]
        && !k.expect.upstream));
    assert!(has(Phase::SignedIn, &|k| k.path == "/"));
    assert!(has(Phase::SignedIn, &|k| !k.send.is_empty() && !k.expect.plain));
    assert!(has(Phase::Revoked, &|k| !k.expect.upstream));
    assert!(has(Phase::AccessDown, &|k| !k.expect.upstream));
}
