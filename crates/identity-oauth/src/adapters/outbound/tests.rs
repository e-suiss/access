#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;
use crate::adapters::clients::{CachePolicy, classify};
use crate::ports::oauth::PostFailure;

// §14.3, RFC 7523
#[test]
fn targets_are_https_only() {
    let t = Target::parse("https://Shop.Example/jwks.json?v=1").unwrap();
    assert_eq!(
        (t.host.as_str(), t.port, t.path.as_str()),
        ("shop.example", 443, "/jwks.json?v=1")
    );
    let t = Target::parse("https://shop.example:8443").unwrap();
    assert_eq!((t.port, t.path.as_str()), (8443, "/"));
    assert_eq!(t.host_header(), "shop.example:8443");
    let t = Target::parse("https://[2606:4700::1]/k").unwrap();
    assert_eq!(t.host_header(), "[2606:4700::1]");
    for bad in [
        "http://shop.example/jwks",
        "https://user@shop.example/jwks",
        "https://shop.example/jwks#frag",
        "https://shop.example/a b",
        "https://shop.example:0/",
        "https://shop.example:99999/",
        "https:///jwks",
        "https://[::1/",
        "ftp://shop.example",
    ] {
        assert_eq!(Target::parse(bad), Err(OutboundError::Url), "{bad}");
    }
}

// §14.3
#[test]
fn only_public_addresses_are_reached() {
    for blocked in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "255.255.255.255",
        "192.0.2.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "fd00:ec2::254",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::a00:1",
        "2002:7f00:1::",
        "2001::1",
    ] {
        assert!(!public(blocked.parse().unwrap()), "{blocked}");
    }
    for open in [
        "93.184.215.14",
        "1.1.1.1",
        "2606:4700::1111",
        "::ffff:1.1.1.1",
    ] {
        assert!(public(open.parse().unwrap()), "{open}");
    }
}

// §14.3 (S-5)
#[test]
fn wrapped_and_bracketed_addresses_are_not_a_way_around() {
    for blocked in [
        "::ffff:0:127.0.0.1",
        "::ffff:0:169.254.169.254",
        "::ffff:0:10.0.0.1",
        "64:ff9b:1::a00:1",
        "64:ff9b:1:abcd::1",
        "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
    ] {
        assert!(!public(blocked.parse().unwrap()), "{blocked}");
    }
    assert!(public("::ffff:0:1.1.1.1".parse().unwrap()));
    assert!(public("64:ff9b::101:101".parse().unwrap()));
    for bad in [
        "https://[2606:4700::1]x/",
        "https://[2606:4700::1].evil.example/",
        "https://[2606:4700::1]8443/",
        "https://[2606:4700::1]]/",
    ] {
        assert_eq!(Target::parse(bad), Err(OutboundError::Url), "{bad}");
    }
    let t = Target::parse("https://[2606:4700::1]:8443/k").unwrap();
    assert_eq!(t.port(), 8443);
    assert_eq!(Target::parse("https://[2606:4700::1]").unwrap().port(), 443);
}

// §14.3
#[tokio::test]
async fn literal_private_hosts_are_refused_before_connecting() {
    for url in [
        "https://127.0.0.1/jwks",
        "https://[::1]/jwks",
        "https://10.0.0.1/",
    ] {
        let t = Target::parse(url).unwrap();
        assert_eq!(resolve(&t).await, Err(OutboundError::Blocked), "{url}");
    }
}

// §14.3, OP-92
#[tokio::test]
async fn other_ports_and_missing_anchors_reach_nothing() {
    let off = Outbound::disabled(Duration::from_secs(1));
    assert_eq!(
        off.get("https://shop.example:8443/jwks", "*/*", 16).await,
        Err(OutboundError::Blocked)
    );
    assert_eq!(
        off.post_form("https://1.1.1.1/logout", "a=b").await,
        Err(OutboundError::Unreachable)
    );
}

async fn answer(raw: &'static [u8], max_body: usize) -> Result<Answer, OutboundError> {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        server.write_all(raw).await.unwrap();
        server.shutdown().await.unwrap();
    });
    read_answer(&mut client, max_body).await
}

// §14.3
#[tokio::test]
async fn answers_are_bounded() {
    let a = answer(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nCache-Control: public, max-age=120\r\n\r\nhello",
        64,
    )
    .await
    .unwrap();
    assert_eq!(
        (a.status, a.max_age_s, a.body.as_slice()),
        (200, Some(120), &b"hello"[..])
    );
    let a = answer(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n",
        64,
    )
    .await
    .unwrap();
    assert_eq!(a.body, b"abcde");
    let a = answer(
        b"HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n\r\nuntil-close",
        64,
    )
    .await
    .unwrap();
    assert_eq!(
        (a.max_age_s, a.body.as_slice()),
        (Some(0), &b"until-close"[..])
    );
    assert_eq!(
        answer(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 64).await,
        Err(OutboundError::Malformed)
    );
    assert_eq!(
        answer(b"HTTP/1.1 200 OK\r\n\r\n0123456789", 4).await,
        Err(OutboundError::Malformed)
    );
    assert_eq!(
        answer(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort", 64).await,
        Err(OutboundError::Unreachable)
    );
    assert_eq!(
        answer(b"garbage\r\n\r\n", 64).await,
        Err(OutboundError::Malformed)
    );
}

// §14.3
#[tokio::test]
async fn redirects_are_not_followed() {
    let a = answer(
        b"HTTP/1.1 302 Found\r\nLocation: https://169.254.169.254/\r\nRetry-After: 3\r\n\r\n",
        0,
    )
    .await
    .unwrap();
    assert_eq!((a.status, a.retry_after_s, a.body.len()), (302, Some(3), 0));
}

// OIDC §2.8
#[test]
fn backchannel_answers_are_classified() {
    assert_eq!(classify(200, None), Ok(()));
    assert_eq!(classify(204, None), Ok(()));
    assert_eq!(
        classify(400, None),
        Err(PostFailure::Rejected { status: 400 })
    );
    assert_eq!(
        classify(302, None),
        Err(PostFailure::Rejected { status: 302 })
    );
    assert_eq!(
        classify(501, None),
        Err(PostFailure::Rejected { status: 501 })
    );
    assert_eq!(
        classify(503, Some(2)),
        Err(PostFailure::Transient {
            retry_after_ms: Some(2000)
        })
    );
    assert_eq!(
        classify(429, None),
        Err(PostFailure::Transient {
            retry_after_ms: None
        })
    );
}

// RFC 7523, §11.3.6
#[test]
fn jwks_cache_bounds_max_age() {
    let p = CachePolicy::default();
    assert_eq!(p.keep_s(None), 300);
    assert_eq!(p.keep_s(Some(0)), 60);
    assert_eq!(p.keep_s(Some(600)), 600);
    assert_eq!(p.keep_s(Some(86_400)), 3_600);
}

fn tls_with(root: rustls::pki_types::CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

fn other_anchor() -> Arc<rustls::ClientConfig> {
    let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    tls_with(other.cert.der().clone())
}

/// A receiver on a private address and a port other than 443 answering `202`, and the trust
/// anchors its certificate chains to.
async fn private_receiver() -> (u16, Arc<rustls::ClientConfig>) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der.clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let _ = s
                    .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, tls_with(der))
}

async fn deliver(outbound: &Outbound, url: &str) -> Result<u16, OutboundError> {
    outbound
        .post(url, "application/secevent+jwt", &[], b"x.y.z")
        .await
        .map(|a| a.status)
}

// OP-149 m.23, §14.3
#[test]
fn declared_targets_are_canonical_urls() {
    assert!(DeclaredTarget::new("https://work-server:8443/v1/inbound/events", None).is_ok());
    assert_eq!(
        DeclaredTarget::new("https://work-server:8443/v1/inbound/events", None)
            .unwrap()
            .port(),
        8443
    );
    for bad in [
        "http://work-server:8443/v1/inbound/events",
        "https://Work-Server:8443/v1/inbound/events",
        "https://work-server:443/v1/inbound/events",
        "https://work-server:8443",
        "https://u@work-server:8443/v1/inbound/events",
        "https://work-server:8443/v1/inbound/events#f",
        "https://work-server:08443/v1/inbound/events",
    ] {
        assert_eq!(
            DeclaredTarget::new(bad, None).unwrap_err(),
            OutboundError::Url,
            "{bad}"
        );
    }
}

// OP-149 m.23, §14.3
#[test]
fn only_declared_private_endpoints_are_accepted() {
    let url = "https://work-server:8443/v1/inbound/events";
    let none = DeclaredTargets::default();
    let declared = DeclaredTargets::new([String::from(url)]);
    assert!(!none.accepts(url));
    assert!(declared.accepts(url));
    for ok in ["https://work.example/ssf", "https://1.1.1.1/ssf"] {
        assert!(none.accepts(ok), "{ok}");
    }
    for refused in [
        "https://work-server:8443/v1/inbound/events/",
        "https://work-server:8443/v1/inbound/other",
        "https://work-server:9443/v1/inbound/events",
        "https://WORK-server:8443/v1/inbound/events",
        "https://u@work-server:8443/v1/inbound/events",
        "https://work-server:8443/v1/inbound/events#x",
        "http://work-server:8443/v1/inbound/events",
        "https://10.0.0.1/v1/inbound/events",
        "https://[::1]/v1/inbound/events",
        "https://127.0.0.1:8443/v1/inbound/events",
    ] {
        assert!(!declared.accepts(refused), "{refused}");
    }
}

// OP-149 m.23, §14.3, TI-9
#[tokio::test]
async fn a_declared_private_target_is_reached_and_near_misses_are_not() {
    let (port, anchors) = private_receiver().await;
    let url = format!("https://localhost:{port}/v1/inbound/events");
    let plain = Outbound::new(other_anchor(), Duration::from_secs(5));
    assert_eq!(deliver(&plain, &url).await, Err(OutboundError::Blocked));
    let declared = plain.clone().declaring(vec![
        DeclaredTarget::new(&url, Some(anchors.clone())).unwrap(),
    ]);
    assert_eq!(deliver(&declared, &url).await, Ok(202));
    assert_eq!(declared.declared(), DeclaredTargets::new([url.clone()]));
    for near in [
        format!("https://localhost:{port}/v1/inbound/events/"),
        format!("https://localhost:{port}/v1/inbound/other"),
        format!("https://LOCALHOST:{port}/v1/inbound/events"),
        format!("https://127.0.0.1:{port}/v1/inbound/events"),
        format!("https://localhost:{port}/v1/inbound/events?x=1"),
    ] {
        assert_eq!(
            deliver(&declared, &near).await,
            Err(OutboundError::Blocked),
            "{near}"
        );
    }
    assert_eq!(
        deliver(
            &declared,
            &format!("https://u@localhost:{port}/v1/inbound/events")
        )
        .await,
        Err(OutboundError::Url)
    );
    assert_eq!(
        declared.get(&url, "*/*", 16).await.map(|a| a.status),
        Err(OutboundError::Blocked)
    );
    assert_eq!(
        declared.post_form(&url, "a=b").await.map(|a| a.status),
        Err(OutboundError::Blocked)
    );
    let fallback = Outbound::new(anchors, Duration::from_secs(5))
        .declaring(vec![DeclaredTarget::new(&url, None).unwrap()]);
    assert_eq!(deliver(&fallback, &url).await, Ok(202));
}

// OP-149 m.23, CR-12
#[tokio::test]
async fn a_declared_target_with_the_wrong_anchor_is_unreachable() {
    let (port, anchors) = private_receiver().await;
    let url = format!("https://localhost:{port}/v1/inbound/events");
    let wrong = Outbound::new(anchors, Duration::from_secs(5)).declaring(vec![
        DeclaredTarget::new(&url, Some(other_anchor())).unwrap(),
    ]);
    assert_eq!(deliver(&wrong, &url).await, Err(OutboundError::Unreachable));
    let none = Outbound::disabled(Duration::from_secs(5))
        .declaring(vec![DeclaredTarget::new(&url, None).unwrap()]);
    assert_eq!(deliver(&none, &url).await, Err(OutboundError::Unreachable));
}
