#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

const URL: &str = "https://app.example/client.json";

fn doc(extra: &str) -> String {
    format!(
        r#"{{"client_id":"{URL}","client_name":"App","redirect_uris":["https://app.example/cb"]{extra}}}"#
    )
}

// §11.3.2, Ek B 4168
#[test]
fn client_identifier_urls_follow_the_draft_rules() {
    for ok in [
        "https://example.com/client.json",
        "https://example.com:8443/c",
        "https://a.b.example/x/y",
    ] {
        assert_eq!(client_id_url(ok), Ok(()), "{ok}");
    }
    for bad in [
        "http://example.com/client.json",
        "https://example.com",
        "https://example.com/",
        "https://user@example.com/c",
        "https://example.com/c#f",
        "https://example.com/c?q=1",
        "https://example.com/a/../c",
        "https://example.com/./c",
        "https://localhost/c",
        "https://app.localhost/c",
        "https://127.0.0.1/c",
        "https://[::1]/c",
        "https://intranet/c",
        "https://example.com:x/c",
    ] {
        assert_eq!(client_id_url(bad), Err(CimdError::Url), "{bad}");
    }
}

// AS-A2, Ek B 4178
#[test]
fn the_domain_policy_admits_exact_hosts_and_named_subdomains_only() {
    let d = vec![String::from("app.example"), String::from("*.tools.example")];
    assert!(domain_admitted(&d, "app.example"));
    assert!(domain_admitted(&d, "a.tools.example"));
    assert!(!domain_admitted(&d, "tools.example"));
    assert!(!domain_admitted(&d, "eviltools.example"));
    assert!(!domain_admitted(&d, "other.example"));
    assert!(!domain_admitted(&[], "app.example"));
    assert_eq!(host(URL).as_deref(), Some("app.example"));
}

// AS-M11, AS-M13, §11.3.3, Ek B 4169, 4170
#[test]
fn the_document_names_its_url_its_name_and_its_redirects() {
    let d = parse(doc("").as_bytes(), URL).unwrap();
    assert_eq!(d.client_name, "App");
    assert_eq!(d.auth, DocumentAuth::None);
    assert_eq!(d.application_type, ApplicationType::Web);
    assert_eq!(
        parse(doc("").as_bytes(), "https://app.example/other.json"),
        Err(CimdError::ClientId)
    );
    for missing in [
        format!(r#"{{"client_id":"{URL}","redirect_uris":["https://app.example/cb"]}}"#),
        format!(r#"{{"client_id":"{URL}","client_name":"App"}}"#),
        format!(r#"{{"client_id":"{URL}","client_name":"App","redirect_uris":[]}}"#),
        format!(r#"{{"client_id":"{URL}","client_name":"  ","redirect_uris":["https://a.example/cb"]}}"#),
    ] {
        assert_eq!(parse(missing.as_bytes(), URL), Err(CimdError::Missing), "{missing}");
    }
    assert_eq!(parse(b"[]", URL), Err(CimdError::Json));
    assert_eq!(parse(b"{", URL), Err(CimdError::Json));
    let repeated = format!(r#"{{"client_id":"{URL}","client_id":"{URL}","client_name":"A"}}"#);
    assert_eq!(parse(repeated.as_bytes(), URL), Err(CimdError::Json));
    let big = doc(&format!(r#","x":"{}""#, "a".repeat(MAX_DOCUMENT)));
    assert_eq!(parse(big.as_bytes(), URL), Err(CimdError::Json));
}

// §11.3.1, §11.4.5 #14, Ek B 4537, 4624
#[test]
fn a_document_with_a_shared_secret_is_refused() {
    for extra in [
        r#","client_secret":"s""#,
        r#","client_secret_expires_at":0"#,
        r#","token_endpoint_auth_method":"client_secret_basic""#,
        r#","token_endpoint_auth_method":"client_secret_post""#,
        r#","token_endpoint_auth_method":"client_secret_jwt""#,
        r#","token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cLyM6h5lFwpYQjtM0dD0cc"}]}"#,
    ] {
        assert_eq!(parse(doc(extra).as_bytes(), URL), Err(CimdError::Secret), "{extra}");
    }
    let keyed = parse(
        doc(r#","token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://app.example/jwks""#)
            .as_bytes(),
        URL,
    )
    .unwrap();
    assert_eq!(keyed.auth, DocumentAuth::JwksUri(String::from("https://app.example/jwks")));
    assert!(!keyed.rs256);
}

// §11.3.9, §11.4.5 #8, SEP-837, Ek B 4177
#[test]
fn application_type_is_read_from_the_document() {
    let native = doc(r#","application_type":"native""#).replace(
        "https://app.example/cb",
        "http://127.0.0.1/cb",
    );
    assert_eq!(
        parse(native.as_bytes(), URL).unwrap().application_type,
        ApplicationType::Native
    );
    let web_loopback = native.replace("native", "web");
    assert_eq!(parse(web_loopback.as_bytes(), URL), Err(CimdError::Redirect));
    assert_eq!(
        parse(doc(r#","application_type":"desktop""#).as_bytes(), URL),
        Err(CimdError::ApplicationType)
    );
    for bad in ["https://*.app.example/cb", "javascript:alert(1)", "app://cb"] {
        let d = doc("").replace("https://app.example/cb", bad);
        assert_eq!(parse(d.as_bytes(), URL), Err(CimdError::Redirect), "{bad}");
    }
}

// §11.3.6, Ek B 4535
#[test]
fn every_fetchable_member_is_an_https_url() {
    let d = parse(
        doc(r#","logo_uri":"https://cdn.example/l.png","tos_uri":"https://app.example/tos""#)
            .as_bytes(),
        URL,
    )
    .unwrap();
    assert_eq!(
        d.fetched,
        vec!["https://cdn.example/l.png", "https://app.example/tos"]
    );
    for extra in [
        r#","logo_uri":"javascript:alert(1)""#,
        r#","jwks_uri":"http://app.example/jwks""#,
        r#","policy_uri":"file:///etc/passwd""#,
        r#","client_uri":7"#,
    ] {
        assert_eq!(parse(doc(extra).as_bytes(), URL), Err(CimdError::Embedded), "{extra}");
    }
}

// AG-5, Ek B 4175, 4250
#[test]
fn authority_members_and_visual_members_change_apart() {
    let base = parse(doc("").as_bytes(), URL).unwrap();
    let digests = |d: &Document| (d.authority_hash, d.visual_hash);
    let renamed = parse(doc("").replace("\"App\"", "\"App 2\"").as_bytes(), URL).unwrap();
    assert_eq!(change(digests(&base), digests(&renamed)), Change::Visual);
    let unknown = parse(doc(r#","software_version":"2""#).as_bytes(), URL).unwrap();
    assert_eq!(change(digests(&base), digests(&unknown)), Change::None);
    for extra in [
        r#","scope":"openid""#,
        r#","grant_types":["authorization_code"]"#,
        r#","token_endpoint_auth_method":"none""#,
    ] {
        let moved = parse(doc(extra).as_bytes(), URL).unwrap();
        assert_eq!(change(digests(&base), digests(&moved)), Change::Authority, "{extra}");
    }
    let more = doc("").replace(
        r#"["https://app.example/cb"]"#,
        r#"["https://app.example/cb","https://app.example/cb2"]"#,
    );
    let moved = parse(more.as_bytes(), URL).unwrap();
    assert_eq!(change(digests(&base), digests(&moved)), Change::Authority);
    let reordered = format!(
        r#"{{"redirect_uris":["https://app.example/cb"],"client_name":"App","client_id":"{URL}"}}"#
    );
    let same = parse(reordered.as_bytes(), URL).unwrap();
    assert_eq!(change(digests(&base), digests(&same)), Change::None);
}

// §11.3.5, OP-154 m.3 (i), Ek B 4173
#[test]
fn cache_lifetimes_are_clamped_to_the_declared_bounds() {
    assert_eq!(keep_s(None), CACHE_MIN_S);
    assert_eq!(keep_s(Some(0)), CACHE_MIN_S);
    assert_eq!(keep_s(Some(3_600)), 3_600);
    assert_eq!(keep_s(Some(10 * 86_400)), CACHE_MAX_S);
    assert!(new_app(1_000, 1_000 + NEW_APP_MS - 1));
    assert!(!new_app(1_000, 1_000 + NEW_APP_MS));
}

// AG-6, Ek B 4248, 4247
#[test]
fn loopback_only_clients_and_redirect_hosts_are_told() {
    let l = vec![
        String::from("http://localhost/callback"),
        String::from("http://127.0.0.1:8080/callback"),
    ];
    assert!(loopback_only(&l));
    assert!(!loopback_only(&[String::from("https://app.example/cb")]));
    assert_eq!(redirect_hosts(&l), vec!["127.0.0.1", "localhost"]);
}

// OP-154 m.3 (i), Ek B 4174
#[test]
fn only_raster_logos_are_kept() {
    assert_eq!(logo_type("image/png; charset=x"), Some("image/png"));
    assert_eq!(logo_type("image/svg+xml"), None);
    assert!(logo_bytes("image/png", b"\x89PNG\r\n\x1a\nrest"));
    assert!(!logo_bytes("image/png", b"<svg/>"));
    assert!(logo_bytes("image/webp", b"RIFF\0\0\0\0WEBPVP8 "));
}

// §11.8.3, AG-18, Ek B 4488
#[test]
fn the_published_claude_and_chatgpt_documents_resolve() {
    let claude = include_bytes!("../../../tests/fixtures/cimd/claude-code.json");
    let c = parse(claude, "https://claude.ai/oauth/claude-code-client-metadata").unwrap();
    assert_eq!(c.application_type, ApplicationType::Native);
    assert_eq!(c.auth, DocumentAuth::None);
    assert!(loopback_only(&c.redirect_uris));
    let chatgpt = include_bytes!("../../../tests/fixtures/cimd/chatgpt.json");
    let g = parse(chatgpt, "https://chatgpt.com/oauth/client-metadata.json").unwrap();
    assert!(g.rs256, "RS256 opt-in from the document");
    assert_eq!(
        g.auth,
        DocumentAuth::JwksUri(String::from("https://chatgpt.com/oauth/jwks.json"))
    );
}
