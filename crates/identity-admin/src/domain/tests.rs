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
