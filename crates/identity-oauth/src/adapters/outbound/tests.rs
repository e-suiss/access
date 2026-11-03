#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;
use crate::adapters::clients::{CachePolicy, classify};
use crate::ports::oauth::PostFailure;

// §14.3, RFC 7523: only https URLs without user info are requested
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

// §14.3: no loopback, private, link-local (cloud metadata), shared, documentation, multicast
// or reserved address, also wrapped in IPv6
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

// §14.3: an address literal is checked without resolution
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

// §14.3, OP-92: only port 443 is reached, and a client without trust anchors reaches nothing
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

// §14.3: bodies are bounded by length, chunked or read to the close
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

// §14.3: redirects are answers, not followed; a POST reads the head only
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

// OIDC Back-Channel Logout §2.8: 2xx delivered; 4xx and 501 final; 408, 429 and 5xx retried
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

// RFC 7523, §11.3.6: a client's max-age is honoured within bounds
#[test]
fn jwks_cache_bounds_max_age() {
    let p = CachePolicy::default();
    assert_eq!(p.keep_s(None), 300);
    assert_eq!(p.keep_s(Some(0)), 60);
    assert_eq!(p.keep_s(Some(600)), 600);
    assert_eq!(p.keep_s(Some(86_400)), 3_600);
}
