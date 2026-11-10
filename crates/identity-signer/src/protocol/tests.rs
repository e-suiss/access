use super::*;

// CMP-22b, OP-143 m.9 (e), OP-149 m.8, OP-150
#[test]
fn messages_round_trip() {
    let realm = Realm([3; 16]);
    let requests = [
        Request::Ping,
        Request::Open {
            realm,
            alg: JwsAlg::Ed25519,
        },
        Request::Jwks(realm),
        Request::Sign {
            realm,
            typ: String::from("JWT"),
            payload: b"{}".to_vec(),
            at: 42,
        },
        Request::SignCose {
            realm,
            content_type: String::from("application/access-auth-context+cbor"),
            payload: vec![0xa0],
            at: 42,
        },
        Request::CellKey,
        Request::SignCheckpoint {
            body: String::from("cell/identity-audit\n1\nAAAA\n"),
        },
        Request::OpenIssuer {
            realm,
            party: [4; 16],
        },
        Request::SignClaim {
            realm,
            payload: vec![0xa0],
            at: 42,
        },
        // OP-155 m.3 (k)
        Request::SignRs256 {
            realm,
            typ: String::from("JWT"),
            payload: b"{}".to_vec(),
            at: 42,
        },
        Request::SignIssuerRegistration {
            realm,
            registration: crate::issuer::Registration {
                domain: [5; 32],
                nonce: vec![6; 32],
                validity: (1, 2),
                iat: 1,
                pep: String::from("identity"),
                step: crate::issuer::Step::Create,
            },
        },
    ];
    for r in requests {
        let f = encode_request(&r).unwrap();
        let len = frame_len(f[..4].try_into().unwrap()).unwrap();
        assert_eq!(len, f.len() - 4);
        assert_eq!(decode_request(&f[4..]).unwrap(), r);
    }
    let responses = [
        Response::Pong,
        Response::Opened,
        Response::Jwks(String::from(r#"{"keys":[]}"#)),
        Response::Signed {
            token: String::from("a.b.c"),
            kid: [9; 32],
        },
        Response::SignedCose {
            sign1: vec![0xd2, 0x84],
            kid: [8; 32],
        },
        Response::CellKey {
            origin: String::from("cell/identity-audit"),
            vkey: String::from("cell/identity-audit+00000000+AA=="),
        },
        Response::Noted {
            line: String::from("\u{2014} cell/identity-audit AAAA\n"),
        },
        Response::Issuer {
            party: [4; 16],
            key: [7; 32],
            kid: [8; 32],
        },
        Response::Error(String::from("signer-no-key")),
    ];
    for r in responses {
        let f = encode_response(&r).unwrap();
        assert_eq!(decode_response(&f[4..]).unwrap(), r);
    }
}

// OP-143 m.4
#[test]
fn bad_frames_are_refused() {
    let too_big = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
    assert_eq!(frame_len(too_big), Err(FrameError::TooLarge));
    assert_eq!(decode_request(&[0xff]), Err(FrameError::Malformed));
    let short_realm = dcbor::encode(
        &map(vec![("jwks", Value::Bytes(vec![1; 15]))]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(decode_request(&short_realm), Err(FrameError::Malformed));
    // MD-3
    let eddsa = dcbor::encode(
        &map(vec![(
            "open",
            map(vec![
                ("realm", Value::Bytes(vec![1; 16])),
                ("alg", Value::text("EdDSA")),
            ]),
        )]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(decode_request(&eddsa), Err(FrameError::Malformed));
}

// TN-118, §13.2
#[test]
fn key_changes_round_trip() {
    let realm = Realm([3; 16]);
    for r in [
        Request::Rotate {
            realm,
            retire: [5; 32],
        },
        Request::DropKey {
            realm,
            kid: [4; 32],
        },
        Request::SetPolicy {
            realm,
            policy: Policy::REALM,
        },
    ] {
        let f = encode_request(&r).unwrap();
        assert_eq!(decode_request(&f[4..]).unwrap(), r);
    }
    let r = Response::Rekeyed(String::from(r#"{"keys":[]}"#));
    assert_eq!(
        decode_response(&encode_response(&r).unwrap()[4..]).unwrap(),
        r
    );
}

// OP-67 m.1
#[test]
fn traceparent_rides_along() {
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let f = encode_request_traced(&Request::Ping, Some(tp)).unwrap();
    assert_eq!(
        decode_request_traced(&f[4..]).unwrap(),
        (Request::Ping, Some(tp.to_owned()))
    );
    let plain = encode_request(&Request::Ping).unwrap();
    assert_eq!(
        decode_request_traced(&plain[4..]).unwrap(),
        (Request::Ping, None)
    );
    let long = "0".repeat(56);
    assert_eq!(
        encode_request_traced(&Request::Ping, Some(&long)).unwrap(),
        plain
    );
}
