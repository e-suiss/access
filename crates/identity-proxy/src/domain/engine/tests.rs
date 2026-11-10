#![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

use std::collections::BTreeMap;

use super::*;

fn headers(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (String::from(*k), String::from(*v)))
        .collect();
    move |name: &str| map.get(name).cloned()
}

// IDP-30, OP-156 m.3 (l)
#[test]
fn each_engine_names_the_request_in_its_own_headers() {
    let nginx = forwarded(
        Engine::Nginx,
        "GET",
        (None, None),
        headers(&[
            ("x-original-method", "POST"),
            ("x-original-uri", "/wiki/page?id=1"),
            ("x-forwarded-host", "Wiki.Example.com"),
        ]),
    )
    .unwrap();
    assert_eq!(nginx.method, "POST");
    assert_eq!(nginx.host, "wiki.example.com");
    assert_eq!(nginx.path, "/wiki/page");
    assert_eq!(nginx.query.as_deref(), Some("id=1"));
    assert!(!nginx.safe());
    for engine in [Engine::Traefik, Engine::Caddy] {
        let f = forwarded(
            engine,
            "GET",
            (None, None),
            headers(&[
                ("x-forwarded-method", "GET"),
                ("x-forwarded-uri", "/"),
                ("x-forwarded-host", "wiki.example.com"),
                ("x-original-uri", "/admin"),
            ]),
        )
        .unwrap();
        assert_eq!(f.uri(), "/");
        assert!(f.safe());
    }
    let envoy = forwarded(
        Engine::Envoy,
        "DELETE",
        (Some("admin/keys"), Some("x=1")),
        headers(&[("host", "wiki.example.com:8443")]),
    )
    .unwrap();
    assert_eq!(envoy.method, "DELETE");
    assert_eq!(envoy.host, "wiki.example.com:8443");
    assert_eq!(envoy.uri(), "/admin/keys?x=1");
}

// IDP-30, TI-9
#[test]
fn a_request_it_cannot_read_is_refused() {
    let nothing = headers(&[]);
    assert_eq!(
        forwarded(Engine::Nginx, "GET", (None, None), &nothing),
        Err(ForwardError::Method)
    );
    let no_host = headers(&[("x-forwarded-method", "GET"), ("x-forwarded-uri", "/")]);
    assert_eq!(
        forwarded(Engine::Traefik, "GET", (None, None), no_host),
        Err(ForwardError::Host)
    );
    for uri in ["wiki", "/a b", "/a#b", ""] {
        let h = headers(&[
            ("x-forwarded-method", "GET"),
            ("x-forwarded-uri", uri),
            ("x-forwarded-host", "wiki.example.com"),
        ]);
        assert_eq!(
            forwarded(Engine::Caddy, "GET", (None, None), h),
            Err(ForwardError::Uri),
            "{uri}"
        );
    }
    let lower = headers(&[
        ("x-forwarded-method", "get"),
        ("x-forwarded-uri", "/"),
        ("x-forwarded-host", "wiki.example.com"),
    ]);
    assert_eq!(
        forwarded(Engine::Caddy, "GET", (None, None), lower),
        Err(ForwardError::Method)
    );
    assert_eq!(Engine::parse("grpc"), None);
    assert_eq!(Engine::parse("envoy"), Some(Engine::Envoy));
    assert_eq!(Engine::Nginx.redirect_status(), 401);
}

#[test]
fn a_cookie_is_read_by_its_exact_name() {
    let h = Some("a=1; __Host-access-proxy=abc; __Host-access-proxy-state=s");
    assert_eq!(cookie(h, "__Host-access-proxy").as_deref(), Some("abc"));
    assert_eq!(cookie(h, "__Host-access-proxy-state").as_deref(), Some("s"));
    assert_eq!(
        cookie(Some("__Host-access-proxy="), "__Host-access-proxy"),
        None
    );
    assert_eq!(cookie(None, "a"), None);
}
