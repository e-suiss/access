use super::*;
use crate::sig::PureBackend;

fn nonce() -> [u8; 32] {
    let seed = std::format!("{:?}", std::time::SystemTime::now());
    crate::digest::sha256(seed.as_bytes())
}

// TI-RT2, OP-158 m.3 (k)
#[test]
fn a_request_is_padded_and_carries_its_nonce() {
    let n = nonce();
    let packet = request(&n).unwrap();
    assert_eq!(packet.len(), MIN_REQUEST);
    assert_eq!(nonce_of(&packet).unwrap(), n);
    let fields = decode(unframe(&packet).unwrap()).unwrap();
    assert_eq!(
        fields.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        [tag::VER, tag::NONC, tag::ZZZZ]
    );
}

#[test]
fn malformed_messages_are_refused() {
    assert_eq!(decode(&[]), Err(RoughtimeError::Malformed));
    assert_eq!(decode(&0_u32.to_le_bytes()), Err(RoughtimeError::Malformed));
    assert_eq!(
        encode(&[(tag::NONC, &[0; 4]), (tag::VER, &[0; 4])]),
        Err(RoughtimeError::Malformed)
    );
    assert_eq!(
        encode(&[(tag::VER, &[0; 3])]),
        Err(RoughtimeError::Malformed)
    );
    assert_eq!(
        unframe(b"ROUGHTIM\x09\0\0\0abc"),
        Err(RoughtimeError::Malformed)
    );
    assert_eq!(
        verify_response(&PureBackend, &[0; 32], &[], &[0; 32], b"nope"),
        Err(RoughtimeError::Malformed)
    );
}

#[cfg(all(feature = "testing", feature = "signer"))]
mod answered {
    use alloc::boxed::Box;

    use super::*;
    use crate::cose::PublicKey;
    use crate::signer::{Signer as _, SoftSigner};

    fn server(mint: u64, maxt: u64) -> (responder::Responder, [u8; 32]) {
        let (long, _) = SoftSigner::generate_ed25519().unwrap();
        let (online, _) = SoftSigner::generate_ed25519().unwrap();
        let PublicKey::Ed25519(k) = long.public_key() else {
            panic!("ed25519");
        };
        (
            responder::Responder::new(&long, Box::new(online), mint, maxt).unwrap(),
            k,
        )
    }

    // TI-RT2, FA-3, OP-158 m.3 (k)
    #[test]
    fn a_signed_answer_to_this_request_is_a_reading() {
        let (s, key) = server(1_000, 3_000);
        let n = nonce();
        let req = request(&n).unwrap();
        let resp = s.respond(&req, 2_000, 1).unwrap();
        let r = verify_response(&PureBackend, &key, &req, &n, &resp).unwrap();
        assert_eq!(
            r,
            Reading {
                midpoint: 2_000,
                radius: 1
            }
        );
        assert_eq!((r.midpoint_ms(), r.radius_ms()), (2_000_000, 1_000));
    }

    // TI-RT2, FA-3
    #[test]
    fn an_answer_for_another_request_or_key_or_window_is_refused() {
        let (s, key) = server(1_000, 3_000);
        let n = nonce();
        let req = request(&n).unwrap();
        let resp = s.respond(&req, 2_000, 1).unwrap();
        let other = crate::digest::sha256(&n);
        let other_req = request(&other).unwrap();
        assert_eq!(
            verify_response(&PureBackend, &key, &other_req, &other, &resp),
            Err(RoughtimeError::Unrelated)
        );
        let (_, stranger) = server(1_000, 3_000);
        assert_eq!(
            verify_response(&PureBackend, &stranger, &req, &n, &resp),
            Err(RoughtimeError::Signature)
        );
        let late = s.respond(&req, 3_001, 1).unwrap();
        assert_eq!(
            verify_response(&PureBackend, &key, &req, &n, &late),
            Err(RoughtimeError::Window)
        );
        let mut forged = resp.clone();
        let last = forged.len() - 40;
        forged[last] ^= 1;
        assert!(verify_response(&PureBackend, &key, &req, &n, &forged).is_err());
        assert_eq!(
            s.respond(&req[..100], 2_000, 1),
            Err(RoughtimeError::Malformed)
        );
    }
}
