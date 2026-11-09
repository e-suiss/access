use super::*;

fn row(method: &str, jwks: Option<&str>, secret: Option<[u8; 32]>) -> ClientRow {
    ClientRow {
        client_uuid: [1; 16],
        client_id: String::from("cli_x"),
        display_name: String::from("Shop"),
        auth_method: String::from(method),
        jwks_uri: jwks.map(String::from),
        redirect_uris: vec![
            String::from("https://shop.example/cb"),
            String::from("http://127.0.0.1/cb?x=1"),
            String::from("http://[::1]:8000/cb"),
        ],
        active: true,
        secret_hash: secret,
        post_logout_redirect_uris: vec![String::from("https://shop.example/bye")],
        backchannel_logout_uri: None,
        jwks: None,
        platform_product: None,
        service_key: None,
        event_receiver: None,
        require_par: false,
        public_sub: false,
        sector_identifier_uri: None,
        third_party: false,
    }
}

// IDP-7, MUST-NEVER-16, OP-146 m.5 (h), RFC 8252 §7.3
#[test]
fn redirect_uris_match_exactly_with_the_loopback_port_free() {
    let c = Client::from_row(row("none", None, None)).unwrap();
    assert!(c.redirect_allowed("https://shop.example/cb"));
    for bad in [
        "https://shop.example/cb/",
        "https://SHOP.example/cb",
        "https://shop.example/cb?x=1",
        "https://shop.example:443/cb",
        "https://shop.example/c%62",
        "https://shop.example/cb#f",
        "http://shop.example/cb",
    ] {
        assert!(!c.redirect_allowed(bad), "{bad}");
    }
    assert!(c.redirect_allowed("http://127.0.0.1:53111/cb?x=1"));
    assert!(c.redirect_allowed("http://127.0.0.1/cb?x=1"));
    assert!(c.redirect_allowed("http://[::1]:1/cb"));
    for bad in [
        "http://127.0.0.1:53111/cb?x=2",
        "http://127.0.0.1:53111/cb",
        "http://localhost:53111/cb?x=1",
        "http://127.0.0.1:x/cb?x=1",
        "http://[::1]:8000/cb/x",
        "https://127.0.0.1:53111/cb?x=1",
    ] {
        assert!(!c.redirect_allowed(bad), "{bad}");
    }
    assert!(c.post_logout_allowed("https://shop.example/bye"));
    assert!(!c.post_logout_allowed("https://shop.example/bye?x"));
}

// CR-38, TN-15
#[test]
fn rows_that_do_not_fit_the_model_are_no_client() {
    assert_eq!(
        Client::from_row(row("none", None, None)).map(|c| c.client_type()),
        Some(ClientType::Public)
    );
    assert!(Client::from_row(row("client_secret_basic", None, None)).is_none());
    assert!(Client::from_row(row("none", None, Some([0; 32]))).is_none());
    assert!(Client::from_row(row("private_key_jwt", None, None)).is_none());
    let retired = ClientRow {
        active: false,
        ..row("none", None, None)
    };
    assert!(Client::from_row(retired).is_none());
}

// OP-149 m.4, RFC 7523
#[test]
fn private_key_jwt_takes_a_jwks_uri_or_one_key() {
    let one = ClientRow {
        jwks: Some(String::from(r#"{"keys":[]}"#)),
        ..row("private_key_jwt", None, None)
    };
    let c = Client::from_row(one.clone()).unwrap();
    assert_eq!(
        c.auth,
        ClientAuth::PrivateKeyJwtKey {
            jwks: String::from(r#"{"keys":[]}"#)
        }
    );
    assert_eq!(c.client_type(), ClientType::Confidential);
    let p = presented(None, Some("cli_x"), Some(ASSERTION_TYPE), Some("a.b.c"))
        .unwrap()
        .unwrap();
    assert_eq!(check_method(&c, &p), Ok(()));
    let both = ClientRow {
        jwks_uri: Some(String::from("https://shop.example/jwks")),
        ..one
    };
    assert!(Client::from_row(both).is_none());
}

// RFC 6749 §2.3, §2.3.1, CR-38, CR-39
#[test]
fn client_credentials_are_one_method_only() {
    let basic = "Basic Y2xpX3g6czMlMjBjcmV0";
    let p = presented(Some(basic), None, None, None).unwrap().unwrap();
    assert_eq!(
        p,
        Presented::Basic {
            client_id: String::from("cli_x"),
            secret: String::from("s3 cret"),
        }
    );
    let c = Client::from_row(row(
        "client_secret_basic",
        None,
        Some(access_crypto::oauth::secret_digest(b"s3 cret")),
    ))
    .unwrap();
    assert_eq!(check_method(&c, &p), Ok(()));
    let wrong = presented(Some("Basic Y2xpX3g6eA=="), None, None, None)
        .unwrap()
        .unwrap();
    assert_eq!(check_method(&c, &wrong), Err(ClientAuthError::Rejected));
    assert_eq!(
        check_method(&c, &Presented::Id(String::from("cli_x"))),
        Err(ClientAuthError::Method)
    );
    assert_eq!(
        presented(Some(basic), None, Some(ASSERTION_TYPE), Some("a.b.c")),
        Err(ClientAuthError::Malformed)
    );
    assert_eq!(
        presented(Some(basic), Some("cli_y"), None, None),
        Err(ClientAuthError::Malformed)
    );
    assert_eq!(
        presented(None, None, Some("urn:other"), Some("a.b.c")),
        Err(ClientAuthError::Malformed)
    );
    assert_eq!(
        presented(Some("Bearer abc"), None, None, None),
        Err(ClientAuthError::Malformed)
    );
    assert_eq!(presented(None, None, None, None), Ok(None));
    assert_eq!(ClientAuthError::Rejected.error(), "invalid_client");
}

// CR-38, OP-151 m.11 (g)
#[test]
fn a_previous_secret_is_accepted_only_for_its_secret_client() {
    let old = access_crypto::oauth::secret_digest(b"old");
    let c = Client::from_row(row(
        "client_secret_basic",
        None,
        Some(access_crypto::oauth::secret_digest(b"new")),
    ))
    .unwrap();
    let basic = |s: &str| Presented::Basic {
        client_id: String::from("cli_x"),
        secret: String::from(s),
    };
    assert_eq!(
        check_method(&c, &basic("old")),
        Err(ClientAuthError::Rejected)
    );
    assert!(previous_matches(&c, &old, &basic("old")));
    assert!(!previous_matches(&c, &old, &basic("other")));
    let public = Client::from_row(row("none", None, None)).unwrap();
    assert!(!previous_matches(&public, &old, &basic("old")));
}

// MD-10, IDP-24
#[test]
fn only_an_opted_in_client_reads_the_public_sector() {
    let pairwise = Client::from_row(row("none", None, None)).unwrap();
    assert_eq!(pairwise.sector(), pairwise.uuid);
    assert_ne!(pairwise.sector(), PUBLIC_SECTOR);
    let public = Client::from_row(ClientRow {
        public_sub: true,
        ..row("none", None, None)
    })
    .unwrap();
    assert_eq!(public.sector(), PUBLIC_SECTOR);
}

// OP-64 (S-4)
#[test]
fn presented_credentials_do_not_print_their_secrets() {
    let basic = Presented::Basic {
        client_id: String::from("cli_x"),
        secret: String::from("s3cret-value"),
    };
    let assertion = Presented::Assertion {
        client_id: None,
        assertion: String::from("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.sig"),
    };
    let printed = format!("{basic:?} {assertion:?}");
    assert!(!printed.contains("s3cret-value"), "{printed}");
    assert!(!printed.contains("eyJ"), "{printed}");
    assert!(printed.contains("cli_x"));
}

// §11.4.3, RFC 8707, Ek B 4161
#[test]
fn resources_have_one_canonical_form() {
    use super::canonical_resource as c;
    for (given, canonical) in [
        ("https://mcp.example.com/mcp", "https://mcp.example.com/mcp"),
        ("https://mcp.example.com", "https://mcp.example.com"),
        ("https://mcp.example.com/", "https://mcp.example.com"),
        (
            "https://mcp.example.com:8443",
            "https://mcp.example.com:8443",
        ),
        (
            "https://mcp.example.com/server/mcp",
            "https://mcp.example.com/server/mcp",
        ),
        ("HTTPS://MCP.Example.com/Mcp", "https://mcp.example.com/Mcp"),
    ] {
        assert_eq!(c(given).as_deref(), Some(canonical), "{given}");
    }
    for bad in [
        "mcp.example.com",
        "https://mcp.example.com#fragment",
        "https://mcp.example.com/mcp?x=1",
        "http://mcp.example.com/mcp",
        "https://user@mcp.example.com/mcp",
        "https:///mcp",
        "https://mcp.example.com/../x",
    ] {
        assert_eq!(c(bad), None, "{bad}");
    }
}

// IDI-10, IDP-1
#[test]
fn a_url_client_id_is_never_a_local_one() {
    use super::ClientIdKind;
    assert_eq!(
        ClientIdKind::of("cli_0123456789abcdefghjkmnpqrs"),
        ClientIdKind::Local
    );
    for url in [
        "https://app.example/client.json",
        "http://app.example/c",
        "HTTPS://app.example/c",
        "urn:x:y/z",
    ] {
        assert_eq!(ClientIdKind::of(url), ClientIdKind::Url, "{url}");
    }
}
