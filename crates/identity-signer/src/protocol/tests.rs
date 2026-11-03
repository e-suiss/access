use super::*;

// CMP-22b, OP-143 m.9 (e): every message survives its frame
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
        Response::Error(String::from("signer-no-key")),
    ];
    for r in responses {
        let f = encode_response(&r).unwrap();
        assert_eq!(decode_response(&f[4..]).unwrap(), r);
    }
}

// OP-143 m.4: oversized and foreign frames are refused
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
    // MD-3: EdDSA is not an algorithm name
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
