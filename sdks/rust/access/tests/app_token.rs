//! IDP-30 (3), OP-156 m.3 (l): the application verifies the forward-auth application token.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::json::b64url_encode;
use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::key_scope::thumbprint;
use access_sdk::resource::app_token::{
    APP_SKEW_MS, APP_TYP, AppTokenError, AppTokenRules, verify_app_token,
};
use suiss_crypto::signer::{Signer as _, SoftSigner};

const ISS: &str = "https://access.test/realms/acme";
const AUD: &str = "https://wiki.example.com";
const NOW_S: u64 = 1_800_000_000;

fn token(signer: &SoftSigner, typ: &str, claims: &str) -> String {
    let kid = b64url_encode(&thumbprint(&signer.public_key()));
    let header = format!(r#"{{"alg":"ES256","kid":"{kid}","typ":"{typ}"}}"#);
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(claims.as_bytes())
    );
    let sig = signer.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(&sig))
}

fn claims(aud: &str, life: u64) -> String {
    format!(
        r#"{{"iss":"{ISS}","sub":"pairwise-sub-of-wiki","aud":{aud},"iat":{NOW_S},"exp":{},"jti":"{}","decision":"decision-1"}}"#,
        NOW_S + life,
        b64url_encode(&[3; 16])
    )
}

fn one(aud: &str) -> String {
    format!(r#""{aud}""#)
}

fn keys(signer: &SoftSigner) -> KeySet {
    let mut k = KeySet {
        keys: BTreeMap::new(),
        allowed: BTreeSet::from([Algorithm::Es256]),
    };
    k.insert(thumbprint(&signer.public_key()), signer.public_key())
        .unwrap();
    k
}

fn rules(aud: &str, now_s: u64) -> AppTokenRules<'_> {
    AppTokenRules {
        issuer: ISS,
        audience: aud,
        now: now_s * 1000,
        skew_ms: APP_SKEW_MS,
    }
}

// IDP-30 (3), OP-156 m.3 (l), MD-10
#[test]
fn an_application_token_verifies_only_for_its_application_within_sixty_seconds() {
    let realm = SoftSigner::generate_p256().unwrap().0;
    let t = token(&realm, APP_TYP, &claims(&one(AUD), 60));
    let id = verify_app_token(&t, &keys(&realm), &rules(AUD, NOW_S)).unwrap();
    assert_eq!(id.sub, "pairwise-sub-of-wiki");
    assert_eq!(id.decision, "decision-1");
    assert_eq!(
        verify_app_token(
            &t,
            &keys(&realm),
            &rules("https://other.example.com", NOW_S)
        ),
        Err(AppTokenError::Claims),
        "another application refuses it"
    );
    assert_eq!(
        verify_app_token(&t, &keys(&realm), &rules(AUD, NOW_S + 66)),
        Err(AppTokenError::Claims),
        "expired"
    );
    let long = token(&realm, APP_TYP, &claims(&one(AUD), 61));
    assert_eq!(
        verify_app_token(&long, &keys(&realm), &rules(AUD, NOW_S)),
        Err(AppTokenError::Lifetime)
    );
    let id_token = token(&realm, "JWT", &claims(&one(AUD), 60));
    assert_eq!(
        verify_app_token(&id_token, &keys(&realm), &rules(AUD, NOW_S)),
        Err(AppTokenError::Signature),
        "an ID token is not an application token"
    );
    let stranger = SoftSigner::generate_p256().unwrap().0;
    assert_eq!(
        verify_app_token(&t, &keys(&stranger), &rules(AUD, NOW_S)),
        Err(AppTokenError::Signature)
    );
    let list = claims(&format!(r#"["{AUD}","https://other.example.com"]"#), 60);
    assert_eq!(
        verify_app_token(
            &token(&realm, APP_TYP, &list),
            &keys(&realm),
            &rules(AUD, NOW_S)
        ),
        Err(AppTokenError::Claims),
        "one audience only"
    );
    assert_eq!(
        verify_app_token(&"a".repeat(9000), &keys(&realm), &rules(AUD, NOW_S)),
        Err(AppTokenError::Size)
    );
}
