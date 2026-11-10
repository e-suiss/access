#![allow(clippy::unwrap_used, reason = "test code")]

use serde_json::json;

use super::*;

const ISS: &str = "https://idp.example";

fn doc(extra: &Value) -> Vec<u8> {
    let mut d = json!({
        "issuer": ISS,
        "authorization_endpoint": "https://idp.example/authorize",
        "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic"],
    });
    if let (Some(o), Some(e)) = (d.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    d.to_string().into_bytes()
}

// MD-3, OP-155 m.3 (h)
#[test]
fn the_algorithms_come_from_discovery_without_none_or_hmac() {
    let d = discovered(
        &doc(&json!({ "id_token_signing_alg_values_supported": ["none", "HS256", "ES256", "PS256"] })),
        ISS,
        ClientAuthMethod::PrivateKeyJwt,
    )
    .unwrap();
    assert_eq!(d.algorithms, ["ES256"]);
    assert_eq!(
        discovered(
            &doc(&json!({ "id_token_signing_alg_values_supported": ["none", "HS256"] })),
            ISS,
            ClientAuthMethod::PrivateKeyJwt,
        ),
        Err(ConnectionError::Algorithms)
    );
    let d = discovered(&doc(&json!({})), ISS, ClientAuthMethod::PrivateKeyJwt).unwrap();
    assert_eq!(d.algorithms, ["RS256"]);
}

// TN-95, OP-155 m.3 (h)
#[test]
fn discovery_must_name_the_registered_issuer_and_take_the_client_authentication() {
    assert_eq!(
        discovered(
            &doc(&json!({})),
            "https://other.example",
            ClientAuthMethod::PrivateKeyJwt
        ),
        Err(ConnectionError::Issuer)
    );
    assert_eq!(
        discovered(&doc(&json!({})), ISS, ClientAuthMethod::ClientSecretPost),
        Err(ConnectionError::ClientAuth)
    );
    let d = discovered(
        &doc(&json!({ "token_endpoint_auth_signing_alg_values_supported": ["RS256"] })),
        ISS,
        ClientAuthMethod::PrivateKeyJwt,
    )
    .unwrap();
    assert_eq!(d.assertion_alg, Some("RS256"));
    assert_eq!(
        discovered(
            &doc(&json!({ "token_endpoint_auth_signing_alg_values_supported": ["HS256"] })),
            ISS,
            ClientAuthMethod::PrivateKeyJwt,
        ),
        Err(ConnectionError::ClientAuth)
    );
    assert_eq!(
        discovered(
            &doc(&json!({ "token_endpoint": "http://idp.example/token" })),
            ISS,
            ClientAuthMethod::PrivateKeyJwt,
        ),
        Err(ConnectionError::Discovery)
    );
}

// RFC 9207, OP-155 m.3 (h)
#[test]
fn the_response_iss_must_be_the_issuer_and_present_when_advertised() {
    let quiet = discovered(&doc(&json!({})), ISS, ClientAuthMethod::PrivateKeyJwt).unwrap();
    assert!(quiet.check_iss(None).is_ok());
    assert!(quiet.check_iss(Some(ISS)).is_ok());
    assert_eq!(
        quiet.check_iss(Some("https://evil.example")),
        Err(ConnectionError::IssParameter)
    );
    let loud = discovered(
        &doc(&json!({ "authorization_response_iss_parameter_supported": true })),
        ISS,
        ClientAuthMethod::PrivateKeyJwt,
    )
    .unwrap();
    assert_eq!(loud.check_iss(None), Err(ConnectionError::IssParameter));
    assert!(loud.check_iss(Some(ISS)).is_ok());
}

// TN-108, OP-155 m.3 (h)
#[test]
fn ui_locales_are_forwarded_only_when_the_upstream_supports_them() {
    let none = discovered(&doc(&json!({})), ISS, ClientAuthMethod::PrivateKeyJwt).unwrap();
    assert_eq!(none.ui_locales(Some("tr en")), None);
    let some = discovered(
        &doc(&json!({ "ui_locales_supported": ["en", "tr-TR"] })),
        ISS,
        ClientAuthMethod::PrivateKeyJwt,
    )
    .unwrap();
    assert_eq!(
        some.ui_locales(Some("tr-tr de en")).as_deref(),
        Some("tr-tr en")
    );
    assert_eq!(some.ui_locales(Some("de")), None);
    assert_eq!(some.ui_locales(None), None);
}

// IDP-27, §10.1.2 rule 2, OP-155 m.3 (h)
#[test]
fn an_unmapped_acr_is_the_lowest_class() {
    let d = Declared {
        acr: Some(String::from("urn:x:gold")),
        amr: vec![String::from("mfa"), String::from("pwd")],
        auth_time_ms: None,
    };
    assert_eq!(mapped(None, &d), LOWEST);
    let map = AssuranceMap {
        entries: vec![
            MapEntry {
                on: MatchOn::Amr,
                value: String::from("mfa"),
                aal: 2,
                loa_eidas: None,
            },
            MapEntry {
                on: MatchOn::Amr,
                value: String::from("pwd"),
                aal: 1,
                loa_eidas: None,
            },
        ],
    };
    assert_eq!(map.apply(&d).aal, 2);
    let gold = AssuranceMap {
        entries: vec![MapEntry {
            on: MatchOn::Acr,
            value: String::from("urn:x:gold"),
            aal: 3,
            loa_eidas: Some(3),
        }],
    };
    assert_eq!(
        mapped(Some(&gold.to_json()), &d),
        Mapped {
            aal: 3,
            loa_eidas: Some(3)
        }
    );
    let other = Declared {
        acr: Some(String::from("urn:x:silver")),
        ..Declared::default()
    };
    assert_eq!(gold.apply(&other), LOWEST);
    assert_eq!(
        mapped(
            Some("{\"entries\":[{\"match\":\"acr\",\"value\":\"a\",\"aal\":4}]}"),
            &d
        ),
        LOWEST
    );
    assert!(
        AssuranceMap::parse("{\"entries\":[{\"match\":\"acr\",\"value\":\"a\",\"aal\":4}]}")
            .is_err()
    );
}

// OP-155 m.3 (h)
#[test]
fn a_profile_holds_its_rules() {
    let legacy = Profile::legacy(true);
    assert_eq!(legacy.client_auth, ClientAuthMethod::ClientSecretPost);
    assert_eq!(
        Profile::legacy(false).client_auth,
        ClientAuthMethod::PrivateKeyJwt
    );
    let p = Profile::stored(Some("{}"), false).unwrap();
    assert_eq!(p.client_auth, ClientAuthMethod::PrivateKeyJwt);
    assert!(p.check(false).is_ok());
    assert!(p.check(true).is_err(), "a secret with private_key_jwt");
    let unsolicited = Profile {
        allow_unsolicited: true,
        ..p.clone()
    };
    assert!(
        unsolicited.check(false).is_err(),
        "unsolicited is SAML only"
    );
    let entra = Profile {
        subject_key: SubjectKey::TidOid,
        ..p.clone()
    };
    assert_eq!(entra.subject_claims(), ["tid", "oid"]);
    assert!(Profile::stored(Some("{\"x\":1}"), false).is_err());
    assert_eq!(
        Profile::stored(Some(&entra.to_json()), false).unwrap(),
        entra
    );
    let unknown = Profile {
        preset: Some(String::from("nope")),
        ..p
    };
    assert!(unknown.check(false).is_err());
}

// IDP-34, OP-155 m.3 (h)
#[test]
fn the_e_devlet_and_mobile_signature_presets_are_data_with_a_sealed_national_id() {
    let ids: Vec<_> = UpstreamPreset::all()
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(ids, ["edevlet", "mobile-signature"]);
    for p in UpstreamPreset::all() {
        assert_eq!(p.national_id.as_deref(), Some("tckn"));
    }
}

// INV-17, OP-155 m.3 (h)
#[test]
fn the_issuer_id_and_the_evidence_are_digests() {
    assert_eq!(issuer_id(ISS), issuer_id(ISS));
    assert_ne!(issuer_id(ISS), issuer_id("https://idp.example/"));
    assert_ne!(evidence(b"a"), evidence(b"b"));
    let claims = json!({ "acr": "x", "amr": ["mfa", 7, "otp"], "auth_time": 1_800_000_000 });
    let d = declared(&claims);
    assert_eq!(d.amr, ["mfa", "otp"]);
    assert_eq!(d.auth_time_ms, Some(1_800_000_000_000));
}
