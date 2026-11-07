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
        require_par: false,
        subject: crate::domain::Subject::default(),
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
    assert_eq!(
        c.check(&DeclaredTargets::default()),
        Err(Invalid::RedirectUris)
    );
    c.redirect_uris.pop();
    assert_eq!(c.check(&DeclaredTargets::default()), Ok(()));
    c.display_name = String::new();
    assert_eq!(
        c.check(&DeclaredTargets::default()),
        Err(Invalid::DisplayName)
    );
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
    assert_eq!(low.check(&DeclaredTargets::default()), Err(Invalid::Argon2));
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
            product: PlatformProduct::parse("work").unwrap(),
            service_key: key,
            event_receiver: Some(String::from("https://work.example/ssf")),
        }),
        ..client(&["https://work.example/cb"])
    };
    assert_eq!(c.check(&DeclaredTargets::default()), Ok(()));
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
        assert_eq!(
            c.check(&DeclaredTargets::default()),
            Err(Invalid::EventReceiver),
            "{bad}"
        );
    }
    if let Some(p) = c.platform.as_mut() {
        p.event_receiver = None;
    }
    assert_eq!(c.check(&DeclaredTargets::default()), Ok(()));
    assert_ne!(Change::ClientRegister(c).digest().unwrap(), with);
}

// OP-149 m.23, §14.3: a suiss_event_receiver on a private address literal or another port than
// 443 is accepted only when the operator declared that exact URL
#[test]
fn a_private_event_receiver_must_be_declared() {
    let url = "https://work-server:8443/v1/inbound/events";
    let declared = DeclaredTargets::new([String::from(url)]);
    let mut c = Client {
        auth: AuthMethod::PrivateKeyJwtKey { key: p256() },
        platform: Some(Platform {
            product: PlatformProduct::parse("work").unwrap(),
            service_key: p256(),
            event_receiver: Some(String::from(url)),
        }),
        ..client(&["https://work.example/cb"])
    };
    assert_eq!(c.check(&declared), Ok(()));
    assert_eq!(
        c.check(&DeclaredTargets::default()),
        Err(Invalid::EventReceiver)
    );
    assert_eq!(Invalid::EventReceiver.code(), "invalid-event-receiver");
    for near in [
        "https://work-server:8443/v1/inbound/events/",
        "https://work-server:8443/v1/inbound/other",
        "https://work-server:9443/v1/inbound/events",
        "https://Work-Server:8443/v1/inbound/events",
        "https://10.0.0.1/v1/inbound/events",
        "https://[::1]/v1/inbound/events",
    ] {
        if let Some(p) = c.platform.as_mut() {
            p.event_receiver = Some(String::from(near));
        }
        assert_eq!(c.check(&declared), Err(Invalid::EventReceiver), "{near}");
    }
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
    assert_eq!(
        c.check(&DeclaredTargets::default()),
        Err(Invalid::ClientKey)
    );
    assert_eq!(Invalid::ClientKey.code(), "client-key-not-p256");
    c.auth = AuthMethod::PrivateKeyJwtKey { key: p256() };
    assert_eq!(c.check(&DeclaredTargets::default()), Ok(()));
    assert!(c.auth.jwks().unwrap().contains(r#""crv":"P-256""#));
}

// RFC 9126 §6, §10.4.3: requiring pushed authorization requests is part of what the
// registration's intent authorizes; a client that does not require them keeps its digest
#[test]
fn requiring_par_is_in_the_change() {
    // RFC 9126
    let c = client(&["https://shop.example/cb"]);
    let without = Change::ClientRegister(c.clone()).digest().unwrap();
    let required = Client {
        require_par: true,
        ..c
    };
    assert_eq!(required.check(&DeclaredTargets::default()), Ok(()));
    assert_ne!(Change::ClientRegister(required).digest().unwrap(), without);
}

// §13.7.7, SEC9: the issuer cutoff is 24 hours before a known compromise, or 7 days before the
// declaration when the compromise time is unknown or claimed to be later
#[test]
fn the_issuer_cutoff_follows_the_margins() {
    let day = 24 * 3_600_000;
    assert_eq!(issuer_cutoff(Some(10 * day), 12 * day), 9 * day);
    assert_eq!(issuer_cutoff(None, 12 * day), 5 * day);
    assert_eq!(issuer_cutoff(Some(13 * day), 12 * day), 5 * day);
    assert_eq!(issuer_cutoff(None, day), 0);
}

// TN-106: branding is data; colours are #rrggbb, CSP origins are bare https origins, the logo
// comes from one of them, and the names are bounded
#[test]
fn branding_is_bounded_data() {
    let ok = Branding {
        display_name: Some(String::from("Acme")),
        logo_uri: Some(String::from("https://cdn.acme.example/l.png")),
        primary_color: Some(Color::parse("#00aaff").unwrap()),
        background_color: None,
        csp_origins: BTreeSet::from([String::from("https://cdn.acme.example")]),
    };
    assert_eq!(ok.check(), Ok(()));
    for bad in ["#00AAFF", "00aaff", "#00aaf", "red"] {
        assert_eq!(Color::parse(bad), Err(Invalid::Branding), "{bad}");
    }
    let path_origin = Branding {
        csp_origins: BTreeSet::from([String::from("https://cdn.acme.example/x")]),
        logo_uri: None,
        ..ok.clone()
    };
    assert_eq!(path_origin.check(), Err(Invalid::Branding));
    let http = Branding {
        csp_origins: BTreeSet::from([String::from("http://cdn.acme.example")]),
        logo_uri: None,
        ..ok.clone()
    };
    assert_eq!(http.check(), Err(Invalid::Branding));
    let long = Branding {
        display_name: Some("x".repeat(MAX_BRAND_NAME + 1)),
        ..ok.clone()
    };
    assert_eq!(long.check(), Err(Invalid::Branding));
    let many = Branding {
        csp_origins: (0..=MAX_CSP_ORIGINS)
            .map(|i| format!("https://c{i}.acme.example"))
            .collect(),
        logo_uri: None,
        ..ok
    };
    assert_eq!(many.check(), Err(Invalid::Branding));
}

// TN-118, §13.2, §13.7.1, OP-73: key policy and rotation are reserved, a drop is narrowing, and
// permanent account deletion is declared reserved; the key changes address the realm's keys
#[test]
fn key_changes_and_deletion_are_declared() {
    let drop = Change::KeyDrop {
        kid: [1; 32],
        compromised_at: None,
    };
    assert!(!drop.action().reserved());
    assert!(Change::KeyRotate { retire: [1; 32] }.action().reserved());
    assert!(Change::KeyPolicy(Policy::REALM).action().reserved());
    assert!(IdpAction::AccountDelete.reserved());
    assert_eq!(IdpAction::AccountDelete.label(), "idp.account.delete");
    assert_eq!(drop.resource("acme").path, ["acme", "keys"]);
    let other = Change::KeyDrop {
        kid: [2; 32],
        compromised_at: None,
    };
    assert_ne!(drop.digest().unwrap(), other.digest().unwrap());
}

// OP-150 m.3 (m), MUST-NEVER-13, XI-18, PI-13: platform_product is a role; a third party's
// product is checked by the same rules as Suiss Work, with the same refusals, and the name is
// part of the authorized change, not a switch the code reads
#[test]
fn a_third_party_platform_product_is_checked_like_a_first_party_one() {
    // OP-149 m.4, CT2
    let platform = |name: &str, auth: AuthMethod| Client {
        auth,
        platform: Some(Platform {
            product: PlatformProduct::parse(name).unwrap(),
            service_key: p256(),
            event_receiver: Some(String::from("https://product.example/ssf")),
        }),
        ..client(&["https://product.example/cb"])
    };
    let mut digests = Vec::new();
    for name in ["work", "acme-ledger"] {
        let ok = platform(name, AuthMethod::PrivateKeyJwtKey { key: p256() });
        assert_eq!(ok.check(&DeclaredTargets::default()), Ok(()), "{name}");
        assert_eq!(
            Change::ClientRegister(ok.clone()).action(),
            IdpAction::ClientRegister
        );
        digests.push(Change::ClientRegister(ok).digest().unwrap());
        for auth in [AuthMethod::None, AuthMethod::ClientSecretBasic] {
            assert_eq!(
                platform(name, auth).check(&DeclaredTargets::default()),
                Err(Invalid::PlatformAuth),
                "{name}"
            );
        }
        let mut bad = platform(name, AuthMethod::PrivateKeyJwtKey { key: p256() });
        if let Some(p) = bad.platform.as_mut() {
            p.event_receiver = Some(String::from("http://product.example/ssf"));
        }
        assert_eq!(
            bad.check(&DeclaredTargets::default()),
            Err(Invalid::EventReceiver),
            "{name}"
        );
    }
    assert_ne!(digests[0], digests[1]);
}
