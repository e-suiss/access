#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

fn keyed() -> ClientAuth {
    ClientAuth::PrivateKeyJwt {
        jwks_uri: String::from("https://c.example/jwks"),
    }
}

fn secret() -> ClientAuth {
    ClientAuth::SecretBasic { digest: [1; 32] }
}

fn fapi() -> ClientProfile {
    ClientProfile {
        fapi2: true,
        ..ClientProfile::default()
    }
}

// IDP-12, OP-155 m.3 (k), Ek B 5044: confidential, private_key_jwt or mTLS, no RSA, no bearer
#[test]
fn fapi2_refuses_public_secret_rsa_and_bearer_clients() {
    assert_eq!(check(&keyed(), &fapi()), Ok(()));
    assert_eq!(
        check(&ClientAuth::None, &fapi()),
        Err(ProfileRefusal::FapiPublic)
    );
    assert_eq!(check(&secret(), &fapi()), Err(ProfileRefusal::FapiMethod));
    let post = ClientProfile {
        legacy: Some(LegacyAuth::SecretPost),
        ..fapi()
    };
    assert_eq!(check(&secret(), &post), Err(ProfileRefusal::FapiMethod));
    let rsa = ClientProfile {
        rs256: true,
        ..fapi()
    };
    assert_eq!(check(&keyed(), &rsa), Err(ProfileRefusal::FapiRsa));
    let bearer = ClientProfile {
        legacy_bearer: true,
        ..fapi()
    };
    assert_eq!(check(&keyed(), &bearer), Err(ProfileRefusal::FapiBearer));
    let mtls = ClientProfile {
        tls: Some(TlsAuth::Pki(TlsName::Dns(String::from("c.example")))),
        ..fapi()
    };
    assert_eq!(check(&secret(), &mtls), Ok(()));
}

// §10.4.3, Ek B 4854: browser, mobile and SPA clients bind with DPoP; M2M and FAPI either way
#[test]
fn public_clients_never_use_mutual_tls() {
    let mtls = ClientProfile {
        tls: Some(TlsAuth::SelfSigned {
            jwks: String::from(r#"{"keys":[]}"#),
        }),
        ..ClientProfile::default()
    };
    assert_eq!(
        check(&ClientAuth::None, &mtls),
        Err(ProfileRefusal::PublicMtls)
    );
    assert_eq!(check(&keyed(), &mtls), Ok(()));
    let bearer = ClientProfile {
        legacy_bearer: true,
        ..ClientProfile::default()
    };
    assert_eq!(
        check(&ClientAuth::None, &bearer),
        Err(ProfileRefusal::PublicBearer)
    );
}

// CR-38, OP-148 m.16 (l), MD-6
#[test]
fn legacy_methods_and_rs256_need_their_basis() {
    let post = ClientProfile {
        legacy: Some(LegacyAuth::SecretPost),
        ..ClientProfile::default()
    };
    assert_eq!(check(&secret(), &post), Ok(()));
    assert_eq!(
        check(&keyed(), &post),
        Err(ProfileRefusal::LegacyWithoutSecret)
    );
    let rs = ClientProfile {
        id_alg: Some(IdAlg::Rs256),
        ..ClientProfile::default()
    };
    assert_eq!(check(&keyed(), &rs), Err(ProfileRefusal::Rs256WithoutOptIn));
    let both = ClientProfile {
        legacy: Some(LegacyAuth::SecretPost),
        tls: Some(TlsAuth::Pki(TlsName::Dns(String::from("c")))),
        ..ClientProfile::default()
    };
    assert_eq!(check(&secret(), &both), Err(ProfileRefusal::TwoMethods));
}

#[test]
fn rows_round_trip_and_inconsistent_rows_are_refused() {
    let p = ClientProfile {
        tls: Some(TlsAuth::Pki(TlsName::SubjectDn(String::from(
            "CN=c,O=Acme",
        )))),
        rs256: true,
        id_alg: Some(IdAlg::Rs256),
        encryption: Some(Encryption {
            alg: KeyAlg::EcdhEsA256kw,
            jwks: String::from(r#"{"keys":[]}"#),
            id_token: true,
            userinfo: false,
            jarm: true,
        }),
        frontchannel: Some(String::from("https://c.example/fc")),
        ..ClientProfile::default()
    };
    assert_eq!(ClientProfile::from_row(p.to_row()), Some(p));
    let mut row = fapi().to_row();
    row.rs256 = true;
    assert_eq!(ClientProfile::from_row(row), None);
    let mut row = ClientProfile::default().to_row();
    row.enc_alg = Some(String::from("RSA1_5"));
    row.enc_jwks = Some(String::from("{}"));
    assert_eq!(ClientProfile::from_row(row), None);
}

#[test]
fn bindings_name_their_confirmation() {
    let j = Binding::Dpop(Jkt([1; 32]));
    assert_eq!(j.token_type(), "DPoP");
    assert!(j.confirmation().unwrap().get("jkt").is_some());
    let m = Binding::Mtls([2; 32]);
    assert_eq!(m.token_type(), "Bearer");
    assert!(m.confirmation().unwrap().get("x5t#S256").is_some());
    assert_eq!(Binding::Bearer.confirmation(), None);
}
