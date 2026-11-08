use access_kernel::combinator::Capacity;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;
use access_kernel::verify::cose::Algorithm;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};

use super::*;

const NOW: u64 = 1_800_000_000_000;
const ISSUER: &str = "https://id.example/realms/acme";

fn signer() -> SoftSigner {
    SoftSigner::generate_p256().unwrap().0
}

fn jws(s: &SoftSigner, typ: &str, payload: &[u8]) -> String {
    let kid = b64url_encode(&thumbprint(&s.public_key()));
    let header = format!(r#"{{"alg":"ES256","kid":"{kid}","typ":"{typ}"}}"#);
    let mut out = b64url_encode(header.as_bytes());
    out.push('.');
    out.push_str(&b64url_encode(payload));
    let sig = s.sign(out.as_bytes()).unwrap();
    out.push('.');
    out.push_str(&b64url_encode(&sig));
    out
}

fn keys(s: &SoftSigner) -> KeySet {
    let mut k = KeySet::default();
    k.insert(thumbprint(&s.public_key()), s.public_key())
        .unwrap();
    k.allowed.insert(Algorithm::Es256);
    k
}

fn facts(surface: &Surface, sid: Option<[u8; 16]>) -> ReadFacts<'_> {
    ReadFacts {
        issuer: ISSUER,
        surface,
        sub: "acc_1",
        client_id: CONSOLE_CLIENT,
        instance: [7; 32],
        jkt: [9; 32],
        console_session: sid,
        rev: Some(3),
        now_ms: NOW,
        ttl_ms: READ_TTL_MS,
    }
}

// TN-130, OP-151 m.3 (a)
#[test]
fn surfaces_have_one_audience_and_one_read_scope() {
    let realm = Surface::Realm(String::from("acme"));
    assert_eq!(realm.audience(), "access-admin:realm:acme");
    assert_eq!(realm.scope(), "realm.read");
    assert_eq!(Surface::Platform.audience(), "access-admin:platform");
    assert_eq!(Surface::Platform.scope(), "platform.read");
    assert_eq!(Surface::of("access-admin:realm:acme"), Some(realm));
    assert_eq!(
        Surface::of("access-admin:platform"),
        Some(Surface::Platform)
    );
    for bad in [
        "access-admin:realm:",
        "access-admin:realm:Acme",
        "access-admin:realm:a/b",
        "access-admin:platformx",
        "https://id.example/realms/acme",
    ] {
        assert_eq!(Surface::of(bad), None, "{bad}");
    }
    assert_ne!(
        exchange_intent("access-admin:realm:acme", REALM_READ),
        exchange_intent("access-admin:realm:acm", "erealm.read")
    );
}

// TN-130, TN-27, RFC 9068
#[test]
fn read_tokens_round_trip_and_never_outlive_an_hour() {
    let s = signer();
    let surface = Surface::Realm(String::from("acme"));
    let mut f = facts(&surface, Some([4; 16]));
    f.ttl_ms = 10 * MAX_READ_TTL_MS;
    let token = jws(&s, ACCESS_TYP, &read_token_claims(&f, "j1"));
    let c = read_claims(&token, &keys(&s), ISSUER).unwrap();
    assert_eq!(c.aud, "access-admin:realm:acme");
    assert_eq!(c.scopes, ["realm.read"]);
    assert_eq!(c.jkt, [9; 32]);
    assert_eq!(c.instance, [7; 32]);
    assert_eq!(c.console_session, Some([4; 16]));
    assert_eq!(c.rev, Some(3));
    assert_eq!(c.exp_ms - c.iat_ms, MAX_READ_TTL_MS);
    assert!(live(&c, NOW));
    assert!(!live(&c, c.exp_ms));
    assert_eq!(
        unverified_audience(&token).as_deref(),
        Some("access-admin:realm:acme")
    );
}

// TN-130
#[test]
fn read_tokens_refuse_what_the_realm_did_not_issue() {
    let s = signer();
    let surface = Surface::Platform;
    let claims = read_token_claims(&facts(&surface, None), "j1");
    assert_eq!(
        read_claims(&jws(&s, "JWT", &claims), &keys(&s), ISSUER),
        Err(JwtError::Signature)
    );
    assert_eq!(
        read_claims(
            &jws(&s, ACCESS_TYP, &claims),
            &keys(&s),
            "https://other.example"
        ),
        Err(JwtError::Claims)
    );
    assert_eq!(
        read_claims(&jws(&signer(), ACCESS_TYP, &claims), &keys(&s), ISSUER),
        Err(JwtError::Signature)
    );
    let mut v: serde_json::Value = serde_json::from_slice(&claims).unwrap();
    v.as_object_mut().unwrap().remove("cnf");
    let unbound = jws(&s, ACCESS_TYP, v.to_string().as_bytes());
    assert_eq!(
        read_claims(&unbound, &keys(&s), ISSUER),
        Err(JwtError::Claims)
    );
}

fn statement(domain: Digest, intent: Digest, mode: Mode, iat: u64) -> Statement {
    Statement {
        domain,
        nonce: vec![1; 16],
        intent,
        mode,
        pep: String::from("access-identity"),
        capacity: Capacity::Own,
        basis: ExerciseBasis::Public(Id([1; 16])),
        iat,
        exercise: None,
    }
}

fn ais(s: &SoftSigner, st: &Statement) -> String {
    let payload = dcbor::encode(&st.to_value(), Limits::CEILING).unwrap();
    let sign1 = sign_sign1(
        s as &dyn Signer,
        thumbprint(&s.public_key()),
        CONTENT_TYPE,
        &payload,
    )
    .unwrap();
    b64url_encode(&sign1)
}

// TN-130, OP-151 m.3 (c)
#[test]
fn the_exchange_subject_is_a_fresh_check_statement_by_the_instance() {
    let s = signer();
    let domain = Digest([3; 32]);
    let intent = exchange_intent("access-admin:realm:acme", REALM_READ);
    let ok = ais(&s, &statement(domain, intent, Mode::Check, NOW));
    let (bytes, kid) = subject_token(&ok).unwrap();
    assert_eq!(kid, thumbprint(&s.public_key()));
    let key = s.public_key();
    assert!(verify_subject(&bytes, kid, &key, &domain, &intent, NOW).is_ok());
    for (st, why) in [
        (statement(domain, intent, Mode::Commit, NOW), "commit"),
        (
            statement(
                domain,
                exchange_intent(PLATFORM_AUDIENCE, PLATFORM_READ),
                Mode::Check,
                NOW,
            ),
            "intent",
        ),
        (
            statement(Digest([4; 32]), intent, Mode::Check, NOW),
            "domain",
        ),
        (
            statement(domain, intent, Mode::Check, NOW - 2 * AIS_SKEW_MS),
            "stale",
        ),
        (
            statement(domain, intent, Mode::Check, NOW + 2 * AIS_SKEW_MS),
            "future",
        ),
    ] {
        let (b, k) = subject_token(&ais(&s, &st)).unwrap();
        assert_eq!(
            verify_subject(&b, k, &key, &domain, &intent, NOW),
            Err(SubjectError::Rejected),
            "{why}"
        );
    }
    let other = signer().public_key();
    assert_eq!(
        verify_subject(&bytes, kid, &other, &domain, &intent, NOW),
        Err(SubjectError::Rejected)
    );
    assert_eq!(
        subject_token("not base64!").map(|_| ()),
        Err(SubjectError::Format)
    );
    assert_eq!(subject_token("").map(|_| ()), Err(SubjectError::Format));
}

// TN-130 (S-3)
#[test]
fn the_replay_slot_is_the_statements_own_day() {
    let midnight = 20_000 * 86_400_000_u64;
    let late = statement(Digest([1; 32]), Digest([2; 32]), Mode::Check, midnight - 1);
    let (day, key) = replay_slot(&late).unwrap();
    assert_eq!(day, 19_999);
    assert!(verify_window(&late, midnight - 1) && verify_window(&late, midnight + 1));
    assert_eq!(replay_slot(&late), Some((day, key)));
    let mut other = late.clone();
    other.nonce = vec![9; 16];
    assert_ne!(replay_slot(&other).unwrap().1, key);
    let early = statement(Digest([1; 32]), Digest([2; 32]), Mode::Check, midnight);
    assert_eq!(replay_slot(&early).unwrap().0, 20_000);
}

fn verify_window(s: &Statement, now_ms: u64) -> bool {
    let signer = signer();
    let kid = thumbprint(&signer.public_key());
    let sign1 = b64url_decode(&ais(&signer, s)).unwrap();
    verify_subject(
        &sign1,
        kid,
        &signer.public_key(),
        &s.domain,
        &s.intent,
        now_ms,
    )
    .is_ok()
}
