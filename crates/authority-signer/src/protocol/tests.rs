use std::collections::BTreeSet;

use access_kernel::verify::key_scope::SpecVersions;

use super::*;

fn template() -> Template {
    Template {
        domain: Digest([7; 32]),
        genesis: Digest([8; 32]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_alg: Algorithm::Ed25519,
        operational_window_max_ms: 86_400_000,
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: Some(vec![1, 2]),
    }
}

// OP-143 m.4: every message survives its frame
#[test]
fn messages_round_trip() {
    let requests = [
        Request::Open(Box::new(template())),
        Request::Metadata(Digest([7; 32])),
        Request::Sign {
            domain: Digest([7; 32]),
            usage: KeyUsage::StatusList,
            content_type: String::from("application/x"),
            payload: vec![9; 40],
            at: 1234,
        },
    ];
    for r in requests {
        let f = encode_request(&r).unwrap();
        assert_eq!(frame_len(f[..4].try_into().unwrap()).unwrap(), f.len() - 4);
        assert_eq!(decode_request(&f[4..]).unwrap(), r);
    }
    let responses = [
        Response::Opened,
        Response::Metadata(vec![1]),
        Response::Signed {
            sign1: vec![2],
            excerpt: vec![3],
        },
        Response::Error(String::from("signer-no-key")),
    ];
    for r in responses {
        let f = encode_response(&r).unwrap();
        assert_eq!(decode_response(&f[4..]).unwrap(), r);
    }
}

// OP-143 m.4: an oversized or malformed frame is refused
#[test]
fn bad_frames_are_refused() {
    let too_big = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
    assert_eq!(frame_len(too_big), Err(FrameError::TooLarge));
    assert_eq!(decode_request(&[0xa0]), Err(FrameError::Malformed));
    assert_eq!(decode_request(&[0xff]), Err(FrameError::Malformed));
}
