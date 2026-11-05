#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

fn client(uris: &[&str]) -> Client {
    Client {
        id: ClientId::parse("cli_0123456789abcdefghjkmnpqrs").unwrap(),
        display_name: String::from("Shop"),
        auth: AuthMethod::None,
        redirect_uris: uris
            .iter()
            .map(|u| RedirectUri::parse(u).unwrap())
            .collect(),
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        platform: None,
    }
}

// IDP-7, RFC 9700 §4.1.3, RFC 8252 §7: redirect URIs are exact strings of allowed shapes;
// patterns, fragments and non-loopback http are refused
#[test]
fn redirect_uris_are_exact_and_constrained() {
    // IDP-7, SA-45, AS-M5, LFP-25
    for ok in [
        "https://shop.example/cb",
        "https://shop.example:8443/cb?x=1",
        "http://127.0.0.1/cb",
        "http://127.0.0.1:49152/cb",
        "http://[::1]:8080/cb",
        "com.example.app:/oauth2redirect",
    ] {
        assert_eq!(RedirectUri::parse(ok).unwrap().as_str(), ok);
    }
    for bad in [
        "",
        "https://*.shop.example/cb",
        "https://shop.example/cb#frag",
        "https://user@shop.example/cb",
        "http://shop.example/cb",
        "http://localhost/cb",
        "javascript:alert(1)",
        "https:///cb",
        "https://shop.example/c b",
        "shop.example/cb",
    ] {
        assert_eq!(RedirectUri::parse(bad), Err(Invalid::RedirectUri), "{bad}");
    }
    let mut c = client(&["https://shop.example/cb", "https://shop.example/cb"]);
    assert_eq!(c.check(), Err(Invalid::RedirectUris));
    c.redirect_uris.pop();
    assert_eq!(c.check(), Ok(()));
    c.display_name = String::new();
    assert_eq!(c.check(), Err(Invalid::DisplayName));
}

// TN-15, OP-137: the client_id is the opaque `cli_` form only
#[test]
fn client_ids_are_opaque() {
    // TN-20
    assert!(ClientId::parse("cli_0123456789abcdefghjkmnpqrs").is_ok());
    for bad in [
        "cli_0123456789abcdefghjkmnpqri",
        "cli_0123",
        "usr_0123456789abcdefghjkmnpqrs",
        "my-app",
    ] {
        assert_eq!(ClientId::parse(bad), Err(Invalid::ClientId), "{bad}");
    }
}

// must-never #18, §9.9.4 k.1, P55: reserved protocol claims cannot be defined by a tenant
#[test]
fn reserved_claims_are_refused() {
    // E39, F23, PI-8, TN-117
    for c in RESERVED_CLAIMS {
        assert_eq!(ClaimName::parse(c), Err(Invalid::Claim), "{c}");
    }
    assert!(ClaimName::parse("department").is_ok());
    assert_eq!(ClaimName::parse("Department"), Err(Invalid::Claim));
}

// IDP-5, WebAuthn §5.1.4: the RP ID is the issuer's host or a parent domain of it
#[test]
fn an_rp_id_covers_the_issuer_host() {
    // IDI-4
    let covers = |rp: &str| RpId::parse(rp).unwrap().covers("acme.id.test");
    assert!(covers("acme.id.test"));
    assert!(covers("id.test"));
    assert!(!covers("cme.id.test"));
    assert!(!covers("other.test"));
    assert_eq!(RpId::parse("test"), Err(Invalid::Host));
}

// OP-33, OP-146 m.4 (f): realm Argon2 parameters never go below the canonical or current ones
#[test]
fn argon2_parameters_only_rise() {
    // CR-36
    let base = Argon2Params::CANONICAL;
    let more = Argon2Params {
        m_kib: base.m_kib * 2,
        ..base
    };
    assert!(raises(&more, &base));
    assert!(!raises(&base, &base));
    assert!(!raises(&base, &more));
    let low = Change::Argon2(Argon2Params { t: 1, ..base });
    assert_eq!(low.check(), Err(Invalid::Argon2));
}

// EI-25: the intent binds the change by digest; another change is another intent
#[test]
fn the_intent_binds_the_change() {
    // MD-14, TN-110
    let w = Window { from: 1, until: 2 };
    let a = Change::ClientRegister(client(&["https://shop.example/cb"]));
    let b = Change::ClientRegister(client(&["https://shop.example/cb2"]));
    let ia = a.intent("acme", w).unwrap();
    assert_eq!(ia.opaque.get(CHANGE_PARAM), Some(&a.digest().unwrap()));
    assert_eq!(ia.action, IdpAction::ClientRegister.action_ref());
    assert_eq!(
        ia.resources[0].path,
        ["acme", "client", "cli_0123456789abcdefghjkmnpqrs"]
    );
    assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    let update = Change::ClientUpdate(client(&["https://shop.example/cb"]));
    assert_ne!(a.digest().unwrap(), update.digest().unwrap());
}

// OP-149 m.4: a platform client's suiss_event_receiver is an absolute https URL Access may push
// to, and it is part of what the registration's intent authorizes
#[test]
fn the_event_receiver_is_an_https_url_in_the_change() {
    // RFC 8935
    let mut base = [0x66; 32];
    base[0] = 0x58;
    let key = PublicKey::Ed25519(base);
    let mut c = Client {
        auth: AuthMethod::PrivateKeyJwtKey { key: p256() },
        platform: Some(Platform {
            product: PlatformProduct::Work,
            service_key: key,
            event_receiver: Some(String::from("https://work.example/ssf")),
        }),
        ..client(&["https://work.example/cb"])
    };
    assert_eq!(c.check(), Ok(()));
    let with = Change::ClientRegister(c.clone()).digest().unwrap();
    for bad in [
        "http://work.example/ssf",
        "https://user@work.example/ssf",
        "https://work.example/ssf#x",
        "work.example/ssf",
        "",
    ] {
        if let Some(p) = c.platform.as_mut() {
            p.event_receiver = Some(String::from(bad));
        }
        assert_eq!(c.check(), Err(Invalid::EventReceiver), "{bad}");
    }
    if let Some(p) = c.platform.as_mut() {
        p.event_receiver = None;
    }
    assert_eq!(c.check(), Ok(()));
    assert_ne!(Change::ClientRegister(c).digest().unwrap(), with);
}

/// The P-256 base point, a valid uncompressed SEC1 key.
fn p256() -> PublicKey {
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&[
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
        0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
        0x37, 0xbf, 0x51, 0xf5,
    ]);
    PublicKey::P256(sec1)
}

// OP-149 m.20
// MD-3
#[test]
fn a_client_key_is_p256_because_assertions_are_es256() {
    let mut base = [0x66; 32];
    base[0] = 0x58;
    let mut c = Client {
        auth: AuthMethod::PrivateKeyJwtKey {
            key: PublicKey::Ed25519(base),
        },
        ..client(&["https://shop.example/cb"])
    };
    assert_eq!(c.check(), Err(Invalid::ClientKey));
    assert_eq!(Invalid::ClientKey.code(), "client-key-not-p256");
    c.auth = AuthMethod::PrivateKeyJwtKey { key: p256() };
    assert_eq!(c.check(), Ok(()));
    assert!(c.auth.jwks().unwrap().contains(r#""crv":"P-256""#));
}
