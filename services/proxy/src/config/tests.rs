#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use super::*;

const BASE: &str = r#"
[access]
url = "https://access.example.com:8443"
ca = "/etc/access-proxy/access-ca.pem"
certificate = "/etc/access-proxy/proxy.pem"
key = "/etc/access-proxy/proxy-key.pem"

[listen]
address = "0.0.0.0:443"
certificate = "/etc/access-proxy/tls/app.pem"
key = "/etc/access-proxy/tls/app-key.pem"
"#;

fn with(apps: &str) -> Result<Config, ConfigError> {
    Config::parse(&format!("{BASE}\n{apps}"))
}

// IDP-30 (2), OP-156 m.3 (m)
#[test]
fn one_file_names_access_the_listener_and_each_application() {
    let c = with(
        r#"
[[app]]
policy = "wiki"
host = "Wiki.Example.com"
upstream = "http://127.0.0.1:8080"
plain_headers = true

[[app]]
policy = "grafana"
host = "grafana.example.com:8443"
upstream = "https://grafana.internal:3000"
upstream_ca = "/etc/access-proxy/grafana-ca.pem"
"#,
    )
    .unwrap();
    assert_eq!(c.access.origin.authority(), "access.example.com:8443");
    assert_eq!(c.access.timeout_ms, CHECK_TIMEOUT_MS);
    assert_eq!(c.apps[0].host, "wiki.example.com");
    assert!(c.apps[0].plain_headers);
    assert_eq!(c.apps[1].hostname(), "grafana.example.com");
    assert_eq!(c.apps[1].upstream.scheme, Scheme::Https);
    assert!(!c.apps[1].plain_headers);
}

// IDP-30 (3), OP-156 m.3 (l)
#[test]
fn plain_headers_need_an_upstream_only_the_proxy_reaches() {
    for upstream in [
        "http://wiki:8080",
        "http://10.0.0.5:8080",
        "http://0.0.0.0:8080",
    ] {
        let e = with(&format!(
            "[[app]]\npolicy = \"wiki\"\nhost = \"wiki.example.com\"\nupstream = \"{upstream}\"\nplain_headers = true\n"
        ))
        .unwrap_err();
        assert_eq!(
            e,
            ConfigError::PlainHeadersReachable(String::from("wiki")),
            "{upstream}"
        );
    }
    for upstream in [
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://localhost:8080",
    ] {
        assert!(
            with(&format!(
                "[[app]]\npolicy = \"wiki\"\nhost = \"wiki.example.com\"\nupstream = \"{upstream}\"\nplain_headers = true\n"
            ))
            .is_ok(),
            "{upstream}"
        );
    }
}

// TI-9, IDP-30 (1)
#[test]
fn what_the_file_cannot_say() {
    let app = "[[app]]\npolicy = \"wiki\"\nhost = \"wiki.example.com\"\nupstream = \"http://127.0.0.1:8080\"\n";
    assert_eq!(
        Config::parse(&format!(
            "{}\n{app}",
            BASE.replace("https://access", "http://access")
        ))
        .unwrap_err(),
        ConfigError::Invalid("access.url")
    );
    assert!(matches!(
        with(&format!("{app}failure_mode_allow = true\n")).unwrap_err(),
        ConfigError::Syntax(_)
    ));
    assert_eq!(
        with(&format!(
            "{app}{}",
            app.replace("policy = \"wiki\"", "policy = \"other\"")
        ))
        .unwrap_err(),
        ConfigError::Duplicate(String::from("other"))
    );
    assert_eq!(with("").unwrap_err(), ConfigError::Invalid("app"));
    assert_eq!(
        with(&app.replace("http://127.0.0.1:8080", "https://127.0.0.1:8080")).unwrap_err(),
        ConfigError::Invalid("app.upstream_ca")
    );
    assert_eq!(
        with(&app.replace("http://127.0.0.1:8080", "http://127.0.0.1:8080/path")).unwrap_err(),
        ConfigError::Invalid("app.upstream")
    );
    assert_eq!(
        with(&app.replace("wiki.example.com", "wiki.example.com:443")).unwrap_err(),
        ConfigError::Invalid("app.host")
    );
    assert_eq!(
        with(&app.replace("policy = \"wiki\"", "policy = \"Wiki\"")).unwrap_err(),
        ConfigError::Invalid("app.policy")
    );
}
