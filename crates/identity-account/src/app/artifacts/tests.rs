#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

use access_kernel::json::b64url_encode;
use serde_json::{Value, json};

use super::*;

fn jwt() -> String {
    let nonce = access_crypto::random::bytes::<12>().unwrap();
    format!(
        "{}.{}.{}",
        b64url_encode(br#"{"alg":"ES256","typ":"JWT"}"#),
        b64url_encode(format!(r#"{{"sub":"{}"}}"#, b64url_encode(&nonce)).as_bytes()),
        b64url_encode(&access_crypto::random::bytes::<32>().unwrap())
    )
}

fn opaque() -> String {
    b64url_encode(&access_crypto::random::bytes::<24>().unwrap())
}

// TN-74, OP-157 m.3 (g)
#[test]
fn only_text_formats_are_taken_and_every_image_or_video_is_refused() {
    assert_eq!(format_of("application/json"), Ok(Format::Json));
    assert_eq!(format_of("application/har+json"), Ok(Format::Har));
    assert_eq!(format_of("text/plain; charset=utf-8"), Ok(Format::Log));
    for media in [
        "image/png",
        "image/jpeg",
        "video/mp4",
        "video/webm",
        "application/octet-stream",
        "application/pdf",
        "",
    ] {
        assert_eq!(format_of(media), Err(Refused::Format), "{media}");
    }
}

// §8.16, TN-74, OP-157 m.3 (g)
#[test]
fn a_har_keeps_no_token_cookie_or_authorization_value() {
    let (token, refresh, cookie, code, id_token) = (jwt(), opaque(), opaque(), opaque(), jwt());
    let har = json!({ "log": { "entries": [{
        "request": {
            "url": format!("https://app.test/cb?code={code}&state=x"),
            "headers": [
                { "name": "Authorization", "value": format!("Bearer {token}") },
                { "name": "Cookie", "value": format!("__Host-session={cookie}") },
                { "name": "Accept", "value": "text/html" }
            ],
            "cookies": [{ "name": "__Host-session", "value": cookie }],
            "queryString": [{ "name": "code", "value": code }],
            "postData": { "text": format!("grant_type=refresh_token&refresh_token={refresh}") }
        },
        "response": {
            "headers": [{ "name": "set-cookie", "value": format!("__Host-session={cookie}; Secure") }],
            "content": { "text": format!(r#"{{"access_token":"{token}","id_token":"{id_token}"}}"#) }
        }
    }]}});
    let raw = har.to_string();
    let r = redact(Format::Har, &raw).unwrap();
    for secret in [&token, &refresh, &cookie, &code, &id_token] {
        assert!(!r.text.contains(secret.as_str()), "{secret} in {}", r.text);
    }
    assert!(r.text.contains("text/html"), "{}", r.text);
    assert!(
        r.text
            .contains("https://app.test/cb?code=[redacted]&state=x"),
        "{}",
        r.text
    );
    assert!(r.count >= 8, "{}", r.count);
    let v: Value = serde_json::from_str(&r.text).unwrap();
    assert_eq!(
        v["log"]["entries"][0]["request"]["headers"][0]["value"],
        REDACTED
    );
}

// §8.16, TN-74
#[test]
fn json_members_named_as_secrets_are_redacted_at_any_depth() {
    let token = opaque();
    let doc =
        json!({ "a": [{ "b": { "client_secret": token, "Authorization": "Basic x" } }], "n": 3 });
    let r = redact(Format::Json, &doc.to_string()).unwrap();
    assert!(!r.text.contains(&token));
    assert_eq!(r.count, 2);
    let v: Value = serde_json::from_str(&r.text).unwrap();
    assert_eq!(v["n"], 3);
    let mut deep = String::new();
    for _ in 0..100 {
        deep.push('[');
    }
    for _ in 0..100 {
        deep.push(']');
    }
    assert_eq!(redact(Format::Json, &deep), Err(Refused::Malformed));
    assert_eq!(redact(Format::Har, "not json"), Err(Refused::Malformed));
}

// §8.16, TN-74
#[test]
fn a_log_keeps_no_header_value_token_or_secure_cookie() {
    let (token, cookie, secret) = (jwt(), opaque(), opaque());
    let log = format!(
        "12:00 GET /me\n  Authorization: Bearer {token}\nCookie: a=b\nset-cookie: __Secure-x={cookie}; Path=/\n\
         12:01 token {token} seen\nclient_secret={secret} sent\n{{\"refresh_token\": \"{secret}\"}}\nplain line\n"
    );
    let r = redact(Format::Log, &log).unwrap();
    for s in [&token, &cookie, &secret] {
        assert!(!r.text.contains(s.as_str()), "{s} in {}", r.text);
    }
    assert!(
        r.text.contains("  Authorization: [redacted]\n"),
        "{}",
        r.text
    );
    assert!(r.text.contains("12:00 GET /me\n"));
    assert!(r.text.ends_with("plain line\n"));
    assert_eq!(redact(Format::Log, &r.text).unwrap().count, 0, "idempotent");
}
