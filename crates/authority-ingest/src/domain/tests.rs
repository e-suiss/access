use ed25519_dalek::{Signer as _, SigningKey};

use access_kernel::claim::body;
use access_kernel::json::b64url_encode;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;

use super::*;

const NOW: u64 = 1_800_000_000_000;
const ISS: &str = "https://idp.example";

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

fn pinned(seed: u8) -> Pinned {
    Pinned {
        iss: String::from(ISS),
        aud: String::from("access"),
        keys: vec![public(seed)],
    }
}

pub(crate) fn jws(seed: u8, typ: &str, payload: &str) -> Vec<u8> {
    let kid = b64url_encode(&thumbprint(&public(seed)));
    let header = format!(r#"{{"alg":"Ed25519","kid":"{kid}","typ":"{typ}"}}"#);
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = signing(seed).sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(&sig.to_bytes())).into_bytes()
}

fn frame(p: &Pinned) -> Frame<'_> {
    Frame {
        domain: Digest([1; 32]),
        issuer: Id([5; 16]),
        subject: Id([6; 16]),
        pinned: p,
        now: NOW,
        skew_ms: 60_000,
    }
}

fn id_token(extra: &str) -> String {
    let iat = NOW / 1000 - 10;
    format!(
        r#"{{"iss":"{ISS}","aud":"access","sub":"u-1","iat":{iat},"exp":{},"acr":"urn:acr:2","amr":["pwd","otp"]{extra}}}"#,
        iat + 300
    )
}

// §10.1.2 OIDC row, OP-150 m.3 (i), E26, INV-12, G45, IDI-9: an upstream ID token becomes an
// authentication Claim with the verified iss, acr and amr, the subject pair digested and nothing
// else
#[test]
fn an_id_token_maps_to_an_authentication_claim() {
    let p = pinned(3);
    let token = jws(3, ID_TOKEN_TYP, &id_token(r#","email":"a@example.com""#));
    let m = map_oidc(&token, &frame(&p)).unwrap();
    assert_eq!(m.statement.class, "authentication");
    assert_eq!(m.statement.issuer, Id([5; 16]));
    assert_eq!(m.statement.subject, Id([6; 16]));
    assert!(m.statement.assurance.is_empty());
    assert_eq!(m.subject, subject_digest(ISS, "u-1"));
    let decoded = body::check(&m.statement, m.body.as_deref())
        .unwrap()
        .unwrap();
    let Body::Authentication(a) = decoded else {
        panic!("authentication body");
    };
    assert_eq!(a.method, AuthMethod::Oidc);
    let up = a.upstream.unwrap();
    assert_eq!(up.iss, ISS);
    assert_eq!(up.acr.as_deref(), Some("urn:acr:2"));
    assert_eq!(up.amr, vec![String::from("pwd"), String::from("otp")]);
    assert_eq!(a.evidence, Some(m.evidence));
    let text = String::from_utf8(m.body.unwrap()).unwrap_or_default();
    assert!(!text.contains("a@example.com"));
}

// §9.13 issuer identification (pinned key set), MD-3: only the pinned keys verify, and the
// token must name the pinned iss and aud
#[test]
fn an_id_token_verifies_only_under_the_pinned_key_set() {
    let p = pinned(3);
    let other = jws(4, ID_TOKEN_TYP, &id_token(""));
    assert_eq!(map_oidc(&other, &frame(&p)), Err(Refusal::ISSUER));
    let wrong_typ = jws(3, SET_TYP, &id_token(""));
    assert_eq!(map_oidc(&wrong_typ, &frame(&p)), Err(Refusal::ISSUER));
    let wrong_aud = jws(
        3,
        ID_TOKEN_TYP,
        &id_token("").replace("\"access\"", "\"other\""),
    );
    assert_eq!(map_oidc(&wrong_aud, &frame(&p)), Err(Refusal::CARRIER));
    let mut late = frame(&p);
    late.now = NOW + 3_600_000;
    let token = jws(3, ID_TOKEN_TYP, &id_token(""));
    assert_eq!(map_oidc(&token, &late), Err(Refusal::CARRIER));
    assert_eq!(peek_iss(&token).unwrap(), ISS);
}

fn set(event: &str, subject: &str) -> String {
    format!(
        r#"{{"iss":"{ISS}","aud":"access","iat":{},"jti":"j1","sub_id":{subject},"events":{{"{RISC}{event}":{{}}}}}}"#,
        NOW / 1000
    )
}

// §10.1.2 SET row: RISC account events become account_status Claims; others are refused
#[test]
fn a_set_maps_to_an_account_status_claim() {
    let p = pinned(3);
    let sub = r#"{"format":"iss_sub","iss":"https://idp.example","sub":"u-1"}"#;
    let token = jws(3, SET_TYP, &set("account-disabled", sub));
    let m = map_set(&token, &frame(&p)).unwrap();
    assert_eq!(m.statement.class, "account_status");
    assert_eq!(
        m.statement.value,
        Some(EqValue::Text(String::from("suspended")))
    );
    assert_eq!(m.statement.validity.until, NOW + SET_VALIDITY_MS);
    assert_eq!(m.subject, subject_digest(ISS, "u-1"));
    assert!(body::check(&m.statement, None).is_ok());
    let unknown = jws(3, SET_TYP, &set("sessions-revoked", sub));
    assert_eq!(map_set(&unknown, &frame(&p)), Err(Refusal::EVENT));
    let email = r#"{"format":"email","email":"a@example.com"}"#;
    let token = jws(3, SET_TYP, &set("account-enabled", email));
    assert_eq!(map_set(&token, &frame(&p)), Err(Refusal::CARRIER));
}

// G44, §13.7.4: narrowing classes are never quarantined for quota
#[test]
fn narrowing_claims_are_recognised() {
    let p = pinned(3);
    let f = frame(&p);
    let status = |s: &str| statement(&f, "account_status", EqValue::Text(String::from(s)), 1, 2);
    assert!(narrowing(&status("suspended")));
    assert!(narrowing(&status("tombstone")));
    assert!(!narrowing(&status("active")));
    let terminated = statement(&f, "party_terminated", EqValue::Int(1), 1, 2);
    assert!(narrowing(&terminated));
    let kyc = statement(&f, "kyc", EqValue::Bool(true), 1, 2);
    assert!(!narrowing(&kyc));
}

// TN-42, CI-2: an inbound SSF event's risk signal narrows and is never refused for quota
#[test]
fn inbound_risk_signals_are_never_quota_refused() {
    let p = pinned(3);
    let f = frame(&p);
    let risk = statement(
        &f,
        RISK_SIGNAL,
        EqValue::Text(String::from("ssf.credential-change")),
        1,
        2,
    );
    assert!(narrowing(&risk));
}

// CI-2, TN-46: an SL2 `risk.*` Claim narrows like a risk signal; a risk Claim with assurance
// levels or a bound intent or resource is refused, whatever its value
#[test]
fn risk_claims_never_qualify() {
    let p = pinned(3);
    let f = frame(&p);
    let level = statement(&f, "risk.level", EqValue::Text(String::from("low")), 1, 2);
    assert!(narrowing(&level));
    assert_eq!(check_risk(&level), Ok(()));
    let mut assured = level.clone();
    assured.assurance.insert(String::from("aal"), 2);
    assert_eq!(check_risk(&assured), Err(Refusal::RISK_QUALIFYING));
    let mut bound = statement(
        &f,
        RISK_SIGNAL,
        EqValue::Text(String::from("new_device")),
        1,
        2,
    );
    assert_eq!(check_risk(&bound), Ok(()));
    bound.bound_intent = Some(access_kernel::digest::Digest([7; 32]));
    assert_eq!(check_risk(&bound), Err(Refusal::RISK_QUALIFYING));
    let mut kyc = statement(&f, "kyc", EqValue::Bool(true), 1, 2);
    kyc.assurance.insert(String::from("aal"), 2);
    assert_eq!(check_risk(&kyc), Ok(()));
    assert!(!risk_class("riskless"));
}

// §10.1.2 WebAuthn rows: only a webauthn authentication or a passkey binding with its body
#[test]
fn a_webauthn_carrier_needs_its_body() {
    let auth = Body::Authentication(Authentication {
        method: AuthMethod::Webauthn,
        auth_time: 1,
        statement: None,
        evidence: None,
        webauthn: Some(body::WebauthnDetail {
            aaguid: [0; 16],
            sign_count: 1,
            up: true,
            uv: true,
            be: false,
            bs: false,
        }),
        upstream: None,
    });
    assert!(check_webauthn(Some(&auth)).is_ok());
    assert_eq!(check_webauthn(None), Err(Refusal::CARRIER));
    let Body::Authentication(mut pwd) = auth else {
        return;
    };
    pwd.method = AuthMethod::Password;
    assert_eq!(
        check_webauthn(Some(&Body::Authentication(pwd))),
        Err(Refusal::CARRIER)
    );
}

// §10.1.1, MD-5: the binding Claim's value for an upstream subject is fixed by its digest, and
// the carrier context names only a Party
#[test]
fn binding_value_and_context_round_trip() {
    let d = subject_digest(ISS, "u-1");
    assert_ne!(d, subject_digest(ISS, "u-2"));
    assert_ne!(d, subject_digest("https://other.example", "u-1"));
    assert!(matches!(binding_value(&d), Some(EqValue::Bytes(b)) if b.len() == 32));
    let ctx = context_bytes(&Id([6; 16]));
    assert_eq!(carrier_context(Some(&ctx)), Ok(Id([6; 16])));
    assert_eq!(carrier_context(None), Err(Refusal::CONTEXT));
    assert_eq!(carrier_context(Some(&[0xa0])), Err(Refusal::CONTEXT));
    assert_eq!(check_size(&[], None), Err(Refusal::SIZE));
    assert_eq!(window_start(3_700, 1_000), 3_000);
    assert_eq!(day_of(86_400_000 * 3 + 5), 3);
}

// TN-4, §12.1.1, MD-5: a realm's Claims go to its governing domain and to each consuming domain
// only while that domain's Acceptance is live
#[test]
fn realm_claims_go_to_governing_and_accepting_domains() {
    let gov = Digest([1; 32]);
    let a = Digest([2; 32]);
    let b = Digest([3; 32]);
    let bindings = [
        (b, Bound::Consuming(Id([8; 16]))),
        (gov, Bound::Governing),
        (a, Bound::Consuming(Id([7; 16]))),
    ];
    let live = |_: &Digest, acc: &Id| *acc == Id([7; 16]);
    assert_eq!(targets(&bindings, live), vec![gov, a]);
    assert_eq!(targets(&bindings, |_, _| false), vec![gov]);
}
