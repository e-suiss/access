#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use access_kernel::claim::body::check;

use super::*;

const SUBJECT: [u8; 16] = [1; 16];
const CREDENTIAL: [u8; 20] = [0xc7; 20];
const PUBLIC_KEY: [u8; 40] = [0x9b; 40];

fn placement(now: u64) -> Placement {
    Placement {
        domain: Digest([3; 32]),
        issuer: Id([4; 16]),
        subject: Id([5; 16]),
        instance: Some(Id([6; 16])),
        supersedes: None,
        now,
    }
}

fn passkey() -> ClaimOrder {
    passkey_binding(&PasskeyFacts {
        subject: SUBJECT,
        credential: &CREDENTIAL,
        public_key: &PUBLIC_KEY,
        alg: -7,
        attestation: Some((String::from("packed"), AttestationResult::Verified)),
        aaguid: [7; 16],
        be: true,
        transports: BTreeSet::from([String::from("internal")]),
        at: 100,
    })
}

fn login(bind: Bind) -> ClaimOrder {
    authentication(AuthFacts {
        subject: SUBJECT,
        method: AuthMethod::Webauthn,
        auth_time: 100,
        assurance: BTreeMap::from([
            (String::from("aal"), 2),
            (String::from("phishing_resistant"), 1),
        ]),
        webauthn: Some(WebauthnDetail {
            aaguid: [7; 16],
            sign_count: 3,
            up: true,
            uv: true,
            be: true,
            bs: true,
        }),
        evidence: Some(assertion_evidence(b"ad", b"cd", b"sig")),
        bind,
    })
}

fn all() -> Vec<ClaimOrder> {
    vec![
        login(Bind::Session([8; 16])),
        login(Bind::Statement([9; 32])),
        passkey(),
        device_key_binding(SUBJECT, &PUBLIC_KEY, -8, [6; 16], 100),
        authenticator_removed(SUBJECT, AuthenticatorKind::Passkey, &CREDENTIAL, 100),
        account_status(SUBJECT, "suspended", 100),
        posture(
            SUBJECT,
            attestation_verdict(AttestationResult::Verified),
            "webauthn-attestation",
            Some(Digest([2; 32])),
            Bind::None,
            100,
        ),
        risk(SUBJECT, RiskSignal::NewDevice, Bind::Session([8; 16]), 100),
    ]
}

// OP-150 L2, CMP-8, OP-10: every order survives the outbox
#[test]
fn orders_survive_the_outbox() {
    for o in all() {
        let bytes = o.to_bytes().unwrap();
        assert_eq!(ClaimOrder::from_bytes(&bytes).unwrap(), o);
        assert!(o.kind().starts_with(OUTBOX_PREFIX));
    }
    assert_eq!(ClaimOrder::from_bytes(b"junk"), Err(BadOrder));
}

// L2-CLB-1, L2-CLB-2, L2-CLB-3, §10.1.2, §10.1.5: each order becomes a statement whose value
// fits its class and whose disclosed body matches the value; a withheld body leaves the Claim
// digest-valued
#[test]
fn prepared_claims_fit_their_classes() {
    for o in all() {
        let p = o.prepare(&placement(150)).unwrap();
        let s = &p.statement;
        assert_eq!(Statement::from_bytes(&s.to_bytes().unwrap()).unwrap(), *s);
        let checked = check(s, p.body.as_deref()).unwrap();
        assert_eq!(checked.is_some(), p.body.is_some(), "{}", o.class);
        assert_eq!(
            (s.issuer, s.subject, s.issued_at),
            (Id([4; 16]), Id([5; 16]), 150)
        );
    }
    let posture = all().remove(6).prepare(&placement(150)).unwrap();
    assert!(posture.body.is_none());
    assert!(matches!(posture.statement.value, Some(EqValue::Bytes(ref d)) if d.len() == 32));
}

// §10.1.5 binding, §9.14.1: a session binding resolves to the Instance the session registered,
// a statement binding carries H(AAS) in the envelope and in the body
#[test]
fn bindings_reach_the_envelope() {
    let s = login(Bind::Session([8; 16]))
        .prepare(&placement(150))
        .unwrap()
        .statement;
    assert_eq!(
        (s.bound_instance, s.bound_intent),
        (Some(Id([6; 16])), None)
    );
    let unbound = Placement {
        instance: None,
        ..placement(150)
    };
    let s = login(Bind::Session([8; 16]))
        .prepare(&unbound)
        .unwrap()
        .statement;
    assert_eq!(s.bound_instance, None);
    let p = login(Bind::Statement([9; 32]))
        .prepare(&placement(150))
        .unwrap();
    assert_eq!(p.statement.bound_intent, Some(Digest([9; 32])));
    let body = check(&p.statement, p.body.as_deref()).unwrap();
    assert!(matches!(
        body,
        Some(Body::Authentication(Authentication { statement: Some(Digest(d)), .. })) if d == [9; 32]
    ));
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// K16, E26, §7.9.15.1, §10.1.2 rule 1, §16.3.1 CMP-15.7: a passkey Claim carries only the digest
// of its public material; the credential id and the public key never leave the identity plane
#[test]
fn claims_carry_digests_not_material() {
    for o in [
        passkey(),
        device_key_binding(SUBJECT, &PUBLIC_KEY, -8, [6; 16], 100),
        authenticator_removed(SUBJECT, AuthenticatorKind::Passkey, &CREDENTIAL, 100),
    ] {
        let p = o.prepare(&placement(150)).unwrap();
        for bytes in [p.statement.to_bytes().unwrap(), p.body.unwrap()] {
            assert!(!contains(&bytes, &CREDENTIAL));
            assert!(!contains(&bytes, &PUBLIC_KEY));
        }
    }
}

// IDP-2, K04: adding and removing an authenticator are lines of authenticator_binding Claims
// about the Party; a removal supersedes the last Claim and holds for no time, and neither binds a
// new Instance
#[test]
fn removal_ends_the_authenticator_line() {
    let added = passkey();
    let removed = authenticator_removed(SUBJECT, AuthenticatorKind::Passkey, &CREDENTIAL, 300);
    assert_eq!(added.line, removed.line);
    let p = Placement {
        supersedes: Some(Id([0xaa; 16])),
        instance: None,
        ..placement(300)
    };
    let s = removed.prepare(&p).unwrap().statement;
    assert_eq!(s.supersedes, Some(Id([0xaa; 16])));
    assert_eq!((s.validity.from, s.validity.until), (300, 300));
    assert_eq!(s.bound_instance, None);
    assert_eq!(added.prepare(&p).unwrap().statement.bound_instance, None);
}

// TN-49, §12.3.1: a status Claim is the scalar status, open-ended, on the subject's status line
#[test]
fn status_claims_hold_until_superseded() {
    let s = account_status(SUBJECT, "deactivated", 100)
        .prepare(&placement(150))
        .unwrap()
        .statement;
    assert_eq!(s.value, Some(EqValue::Text(String::from("deactivated"))));
    assert_eq!(s.validity.until, u64::MAX);
    assert_eq!(
        account_status(SUBJECT, "active", 1).line,
        Some(status_line())
    );
}
