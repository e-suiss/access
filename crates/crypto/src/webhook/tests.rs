use super::*;

const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const TS: u64 = 1_614_265_330;
const BODY: &[u8] = br#"{"test": 2432232314}"#;
const EXPECTED: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

// OP-149 m.4: the Standard Webhooks reference vector
#[test]
fn standard_webhooks_known_answer() {
    let s = WebhookSecret::parse(SECRET).unwrap();
    assert_eq!(s.sign(ID, TS, BODY), EXPECTED);
    assert!(s.verify(ID, TS, BODY, EXPECTED, TS));
    assert!(s.verify(ID, TS, BODY, &format!("v1,AAAA {EXPECTED}"), TS + 10));
}

// OP-149 m.4
#[test]
fn tampering_skew_and_other_versions_are_refused() {
    let s = WebhookSecret::parse(SECRET).unwrap();
    assert!(!s.verify(ID, TS, br#"{"test": 2432232315}"#, EXPECTED, TS));
    assert!(!s.verify("msg_other", TS, BODY, EXPECTED, TS));
    assert!(!s.verify(ID, TS, BODY, EXPECTED, TS + TOLERANCE_S + 1));
    assert!(!s.verify(ID, TS, BODY, &EXPECTED.replacen("v1", "v1a", 1), TS));
    let other = WebhookSecret::generate().unwrap();
    assert!(!other.verify(ID, TS, BODY, EXPECTED, TS));
}

// OP-149 m.4, SA-26
#[test]
fn secret_round_trips_and_never_prints() {
    let s = WebhookSecret::generate().unwrap();
    let text = s.expose_text();
    assert!(text.starts_with(SECRET_PREFIX));
    let back = WebhookSecret::parse(&text).unwrap();
    assert_eq!(back.expose_bytes(), s.expose_bytes());
    assert_eq!(format!("{s:?}"), "WebhookSecret(<redacted>)");
    assert!(WebhookSecret::parse("whsec_AAAA").is_err());
    assert!(WebhookSecret::parse("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").is_err());
}

#[test]
fn base64_round_trips() {
    for n in 0..40_u8 {
        let data: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
        assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
    }
    assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
    assert!(b64_decode("Zm9=Yg==").is_none());
    assert!(b64_decode("Zm9").is_none());
}

// TN-136, SA-26: an Ed25519 key round-trips, never prints, and a rotated key overlaps
#[test]
fn tn_136_ed25519_keys_round_trip_and_overlap() {
    let old = WebhookSigningKey::generate().unwrap();
    let new = WebhookSigningKey::generate().unwrap();
    assert_eq!(format!("{old:?}"), "WebhookSigningKey(<redacted>)");
    let again = WebhookSigningKey::from_seed(old.expose_seed()).unwrap();
    assert_eq!(again.public_key(), old.public_key());
    let pk = WebhookPublicKey::parse(&old.public_key().text()).unwrap();
    assert_eq!(pk, old.public_key());
    let header = format!("{} {}", new.sign(ID, TS, BODY), old.sign(ID, TS, BODY));
    assert!(old.public_key().verify(ID, TS, BODY, &header, TS));
    assert!(new.public_key().verify(ID, TS, BODY, &header, TS));
    assert!(
        !old.public_key()
            .verify(ID, TS, BODY, &new.sign(ID, TS, BODY), TS)
    );
    assert!(WebhookSigningKey::from_seed(&[0; 31]).is_err());
    assert!(WebhookPublicKey::parse("whpk_AAAA").is_err());
    assert!(
        !old.public_key()
            .verify(ID, TS, BODY, &old.sign(ID, TS, BODY), TS + TOLERANCE_S + 1)
    );
}
