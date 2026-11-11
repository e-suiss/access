#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::sig::{PureBackend, p256};
use suiss_crypto::signer::{Signer as _, SoftSigner};

fn key() -> (SoftSigner, Vec<u8>) {
    let (signer, _) = SoftSigner::generate_p256().unwrap();
    let PublicKey::P256(public) = signer.public_key() else {
        panic!("p-256")
    };
    (signer, public)
}

// OP-156 m.3 (d)
#[test]
fn an_answer_is_signed_over_its_deterministic_cbor() {
    let (signer, public) = key();
    let t = thumbprint(&public).unwrap();
    let a = Answer {
        challenge: [3; 32],
        number: Some(57),
        decision: Decision::Approve,
        device_key: t,
        pin_verified: Some(true),
    };
    let bytes = a.to_be_signed();
    let v = dcbor::decode(&bytes, Limits::CEILING).unwrap();
    assert_eq!(v.get("number"), Some(&Value::Unsigned(57)));
    assert_eq!(v.get("decision"), Some(&Value::text("approve")));
    let sig = to_raw_signature(&signer.sign(&bytes).unwrap()).unwrap();
    assert!(p256(&PureBackend, &public, &bytes, &sig, true).is_ok());
    let body = answer_body(&bytes, &sig);
    assert!(body.starts_with(r#"{"answer":""#));
}

// CR-9
#[test]
fn a_high_s_or_der_signature_becomes_low_s_raw() {
    let (signer, public) = key();
    let msg = registration_message("https://acme.example", &thumbprint(&public).unwrap());
    let raw = signer.sign(&msg).unwrap();
    let mut high = [0_u8; 64];
    high[..32].copy_from_slice(&raw[..32]);
    let s: [u8; 32] = raw[32..].try_into().unwrap();
    high[32..].copy_from_slice(&sub(&N, &s));
    assert!(p256(&PureBackend, &public, &msg, &high, true).is_err());
    let low = to_raw_signature(&high).unwrap();
    assert!(p256(&PureBackend, &public, &msg, &low, true).is_ok());
    let der_int = |x: &[u8]| {
        let mut v = vec![0x02];
        let lead = x[0] & 0x80 != 0;
        v.push(u8::try_from(x.len()).unwrap() + u8::from(lead));
        if lead {
            v.push(0);
        }
        v.extend_from_slice(x);
        v
    };
    let mut der = der_int(&high[..32]);
    der.extend(der_int(&high[32..]));
    let mut seq = vec![0x30, u8::try_from(der.len()).unwrap()];
    seq.extend(der);
    assert_eq!(to_raw_signature(&seq), Some(low));
    assert!(to_raw_signature(&[0x30, 0]).is_none());
    assert!(to_raw_signature(&[0; 64]).is_none());
}

// OP-156 m.3 (d)
#[test]
fn a_push_names_the_application_and_place_but_never_a_number() {
    let data = br#"{"recipient":{"device":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"challenge":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","application":"Acme","action":"Sign in","location":"TR","expires_at":"2026-11-10T10:00:00Z"}"#;
    let p = PushRequest::parse(data).unwrap();
    assert_eq!(p.challenge, [3; 32]);
    assert_eq!(
        p.prompt(),
        "Sign-in request to Acme from a browser, TR. Enter the number shown."
    );
    let none = br#"{"challenge":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","application":"Acme","action":"Sign in","expires_at":"x"}"#;
    assert_eq!(
        PushRequest::parse(none).unwrap().prompt(),
        "Sign-in request to Acme from a browser. Enter the number shown."
    );
    assert_eq!(PushRequest::parse(b"{}"), Err(NotAPush));
}

// RFC 7638 §3
#[test]
fn bodies_quote_their_text() {
    let body = registration_body("Ada's \"phone\"", &[4; 65], &[1; 64]);
    assert!(body.starts_with(r#"{"name":"Ada's \"phone\"","public_key":""#));
    assert!(thumbprint(&[2; 65]).is_none());
}

// §13.7.3, OP-157 m.3 (m)
#[test]
fn an_inline_body_with_another_render_digest_is_refused_on_the_device() {
    use access_kernel::digest::Digest;
    use access_kernel::render::{self, Field, Render};

    use super::inline::{InlineRequest, approve_to_be_signed, deny_to_be_signed};

    let render = Render {
        schema: Digest([1; 32]),
        intent: Digest([2; 32]),
        locale: "en".into(),
        template: None,
        fields: alloc::vec![Field {
            name: "action".into(),
            text: "Close the ledger".into(),
            material: true,
        }],
        reversibility: None,
    };
    let bytes = render::encode(&render).unwrap();
    let digest = render::digest(&render).unwrap();
    let body = |rendered: &[u8], d: &Digest| {
        alloc::format!(
            r#"{{"intent":"{}","render":"{}","render_digest":"{}","expires_at_ms":5}}"#,
            hex(&render.intent.0),
            access_kernel::json::b64url_encode(rendered),
            hex(&d.0)
        )
        .into_bytes()
    };
    let good = InlineRequest::parse(&body(&bytes, &digest)).unwrap();
    assert_eq!(good.verified().unwrap(), render);
    let bad = InlineRequest::parse(&body(&bytes, &Digest([9; 32]))).unwrap();
    assert!(bad.verified().is_err());

    let deny = deny_to_be_signed(&good, &[3; 32]);
    assert!(deny.windows(4).any(|w| w == b"deny"));
    let _ = approve_to_be_signed;
}

// §10.3.1, OP-157 m.17
#[test]
fn an_inline_approval_carries_the_platform_assertion_over_h_aas() {
    use access_kernel::aas::EvidenceLevel;
    use access_kernel::combinator::Capacity;
    use access_kernel::digest::Digest;
    use access_kernel::model::Id;
    use access_kernel::render::{self, Field, Render};

    use super::inline::{
        InlineRequest, PasskeyAssertion, StatementFacts, approve_body, passkey_challenge,
        statement, statement_digest,
    };

    let shown = Render {
        schema: Digest([1; 32]),
        intent: Digest([2; 32]),
        locale: "en".into(),
        template: None,
        fields: alloc::vec![Field {
            name: "action".into(),
            text: "Close the ledger".into(),
            material: true,
        }],
        reversibility: None,
    };
    let request = InlineRequest {
        intent: shown.intent,
        render: render::encode(&shown).unwrap(),
        render_digest: render::digest(&shown).unwrap(),
        expires_at_ms: 9,
    };
    let act = statement(
        &request,
        &shown,
        StatementFacts {
            class: "approve".into(),
            instance: Id([3; 16]),
            party: Id([4; 16]),
            capacity: Capacity::Own,
            domain: Digest([5; 32]),
            nonce: alloc::vec![6; 16],
            issued_at: 1,
            expires_at: 2,
        },
    );
    assert_eq!(act.evidence, Some(EvidenceLevel::PhishingResistant));
    assert_eq!(
        passkey_challenge(&act).unwrap(),
        statement_digest(&act).unwrap().0
    );

    let mut assertion = PasskeyAssertion {
        credential_id: alloc::vec![1],
        authenticator_data: alloc::vec![2],
        client_data_json: alloc::vec![3],
        signature: alloc::vec![4],
        user_handle: None,
    };
    assert_eq!(
        approve_body(&[7], &[8; 64], &assertion),
        alloc::format!(
            r#"{{"answer":"Bw","signature":"{}","assertion":{{"credential_id":"AQ","authenticator_data":"Ag","client_data_json":"Aw","signature":"BA"}}}}"#,
            access_kernel::json::b64url_encode(&[8; 64])
        )
    );
    assertion.user_handle = Some(alloc::vec![5]);
    assert!(
        approve_body(&[7], &[8; 64], &assertion)
            .ends_with(r#""signature":"BA","user_handle":"BQ"}}"#)
    );
}

fn hex(bytes: &[u8]) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    for b in bytes {
        core::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}")).unwrap();
    }
    out
}
