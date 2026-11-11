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
        declared: crate::domain::declared_default(),
    }
}

// OP-143 m.4
fn superseded() -> access_kernel::verify::key_scope::BindingKey {
    let (k, _) = suiss_crypto::signer::SoftSigner::generate_ed25519().unwrap();
    let mut b = crate::domain::binding(
        suiss_crypto::cose::Algorithm::Ed25519,
        suiss_crypto::signer::Signer::public_key(&k),
    );
    b.superseded = Some(access_kernel::verify::key_scope::Superseded {
        at: Digest([1; 32]),
        cited: Digest([2; 32]),
    });
    b
}

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
        Request::SignNote {
            domain: Digest([7; 32]),
            body: String::from("origin\n0\nAA==\n"),
            at: 5,
        },
        Request::Genesis(Digest([7; 32])),
        Request::SignToken {
            domain: Digest([7; 32]),
            claims: br#"{"cnf":{}}"#.to_vec(),
            at: 6,
        },
        // OP-158 m.3 (f)
        Request::Declare {
            domain: Digest([7; 32]),
            declared: Box::new({
                let mut d = crate::domain::declared_default();
                let (k, _) = suiss_crypto::signer::SoftSigner::generate_ed25519().unwrap();
                d.replicas
                    .push(access_kernel::verify::key_scope::Replica::new(
                        String::from("acme-replica"),
                        suiss_crypto::signer::Signer::public_key(&k),
                        String::from("Acme Replica Ltd"),
                        true,
                    ));
                d
            }),
        },
        // OP-158 m.3 (l)
        Request::Binding {
            domain: Digest([7; 32]),
            next: true,
        },
        Request::Statement {
            domain: Digest([7; 32]),
            next: false,
            content_type: String::from(crate::handover::NO_WRITE),
            payload: vec![0xa0],
        },
        Request::Rebind {
            domain: Digest([7; 32]),
            at: Digest([1; 32]),
            cited: Digest([2; 32]),
            transcript: Digest([3; 32]),
        },
        Request::Supersede {
            domain: Digest([7; 32]),
            keys: vec![superseded()],
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
        Response::Noted {
            line: String::from("\u{2014} origin AAAA\n"),
            excerpt: vec![4],
        },
        Response::Genesis(vec![5]),
        Response::Token {
            jws: String::from("a.b.c"),
            excerpt: vec![6],
        },
        Response::Binding(superseded()),
        Response::Statement(vec![7]),
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
    assert_eq!(decode_request(&[0xa0]), Err(FrameError::Malformed));
    assert_eq!(decode_request(&[0xff]), Err(FrameError::Malformed));
}

// OP-67 m.1
#[test]
fn traceparent_rides_along() {
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let r = Request::Metadata(Digest([7; 32]));
    let f = encode_request_traced(&r, Some(tp)).unwrap();
    assert_eq!(
        decode_request_traced(&f[4..]).unwrap(),
        (r.clone(), Some(tp.to_owned()))
    );
    assert_eq!(decode_request(&f[4..]).unwrap(), r);
    let plain = encode_request(&r).unwrap();
    assert_eq!(
        decode_request_traced(&plain[4..]).unwrap(),
        (r.clone(), None)
    );
    let long = "0".repeat(56);
    assert_eq!(encode_request_traced(&r, Some(&long)).unwrap(), plain);
}
