#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;
use crate::protocol::{decode_request, encode_request};

// OP-159 m.3 (o)
#[test]
fn every_request_reads_back_and_only_ml_dsa_is_named() {
    let realm = Realm([3; 16]);
    for r in [
        PqRequest::Ready {
            alg: JwsAlg::MlDsa65,
        },
        PqRequest::Open {
            realm,
            alg: JwsAlg::MlDsa44,
        },
        PqRequest::Close { realm },
        PqRequest::Sign {
            realm,
            typ: String::from("JWT"),
            payload: br#"{"sub":"a"}"#.to_vec(),
            at: 9,
        },
    ] {
        let request = crate::protocol::Request::Pq(r);
        let frame = encode_request(&request).unwrap();
        let body = frame.get(4..).unwrap();
        assert_eq!(decode_request(body).unwrap(), request);
    }
    let classical = entries(vec![(
        "ready",
        entries(vec![("alg", Value::text("ES256"))]),
    )]);
    assert!(PqRequest::from_value(&classical).is_err());
}

// OP-159 m.3 (o)
#[test]
fn the_post_quantum_keys_follow_the_classical_ones_in_the_jwks() {
    assert_eq!(
        merged(r#"{"keys":[{"a":1}]}"#, r#"{"keys":[{"b":2}]}"#),
        r#"{"keys":[{"a":1},{"b":2}]}"#
    );
    assert_eq!(
        merged(r#"{"keys":[]}"#, r#"{"keys":[{"b":2}]}"#),
        r#"{"keys":[{"b":2}]}"#
    );
    assert_eq!(
        merged(r#"{"keys":[{"a":1}]}"#, r#"{"keys":[]}"#),
        r#"{"keys":[{"a":1}]}"#
    );
    assert_ne!(slot(Realm([1; 16])), Realm([1; 16]));
}
