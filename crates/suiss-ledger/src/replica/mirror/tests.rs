#![cfg(not(target_family = "wasm"))]
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{Signer as _, SoftSigner};

use super::*;

fn frames() -> Vec<Frame> {
    vec![
        Frame::Record {
            position: 7,
            envelope: vec![0xa1],
            body: None,
        },
        Frame::Record {
            position: 8,
            envelope: vec![0xa1, 0x01],
            body: Some(vec![2, 3]),
        },
        Frame::Checkpoint {
            note: String::from("origin\n9\nroot\n\n— log sig\n"),
            cosignatures: vec![b"line".to_vec()],
            excerpt: Some(vec![0x80]),
        },
        Frame::Redaction {
            position: 7,
            dek: redaction_digest(&[0xa1]),
        },
        Frame::Heartbeat {
            size: 9,
            at: 1_767_225_000_000,
        },
    ]
}

// T21, OP-158 m.3 (f)
#[test]
fn every_frame_reads_back_from_a_sequence() {
    let mut seq = Vec::new();
    for f in frames() {
        seq.extend(f.to_bytes().unwrap());
    }
    assert_eq!(read_all(&seq).unwrap(), frames());
    let cut = seq.len() - 1;
    assert_eq!(read_all(&seq[..cut]), Err(WireError));
}

// T21, OP-158 m.3 (f)
#[test]
fn a_frame_with_two_kinds_or_an_unknown_member_is_refused() {
    let two = Value::Map(vec![
        (
            Value::text("heartbeat"),
            Value::Map(vec![
                (Value::text("size"), Value::Unsigned(1)),
                (Value::text("at"), Value::Unsigned(1)),
            ]),
        ),
        (Value::text("record"), Value::Map(Vec::new())),
    ]);
    assert_eq!(Frame::from_value(&two), Err(WireError));
    let extra = Value::Map(vec![(
        Value::text("heartbeat"),
        Value::Map(vec![
            (Value::text("size"), Value::Unsigned(1)),
            (Value::text("at"), Value::Unsigned(1)),
            (Value::text("root"), Value::Unsigned(1)),
        ]),
    )]);
    assert_eq!(Frame::from_value(&extra), Err(WireError));
}

fn public(s: &SoftSigner) -> [u8; 32] {
    match s.public_key() {
        suiss_crypto::cose::PublicKey::Ed25519(k) => k,
        other => panic!("{other:?}"),
    }
}

// TI-13, SEC23
#[test]
fn an_ack_verifies_only_under_its_replicas_key() {
    let (key, _) = SoftSigner::generate_ed25519().unwrap();
    let (other, _) = SoftSigner::generate_ed25519().unwrap();
    let ack = ReplicaAck {
        domain: suiss_crypto::digest::context_digest("test/domain", b"d").0,
        replica: String::from("acme-replica"),
        size: 8,
        root: suiss_crypto::digest::context_digest("test/root", b"r").0,
        at: 1_767_225_000_000,
    };
    let sig = key.sign(&ack.message().unwrap()).unwrap();
    let signed = SignedReplicaAck {
        ack,
        sig: sig.try_into().unwrap(),
    };
    let back = SignedReplicaAck::from_bytes(&signed.to_bytes().unwrap()).unwrap();
    assert_eq!(back, signed);
    back.verify(&PureBackend, &public(&key)).unwrap();
    assert_eq!(back.verify(&PureBackend, &public(&other)), Err(WireError));
    let mut changed = back;
    changed.ack.size = 9;
    assert_eq!(changed.verify(&PureBackend, &public(&key)), Err(WireError));
}

// TI-13
#[test]
fn the_contract_example_reads_and_an_ack_of_nothing_is_malformed() {
    let hex = "a26361636ba56261741b0000019b76d1804064726f6f7458200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b6473697a650866646f6d61696e58200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a677265706c6963616c61636d652d7265706c6963616373696758405d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let example = SignedReplicaAck::from_bytes(&bytes).unwrap();
    assert_eq!(example.ack.size, 8);
    assert_eq!(example.ack.replica, "acme-replica");
    assert_eq!(example.to_bytes().unwrap(), bytes);
    let mut zero = example;
    zero.ack.size = 0;
    assert_eq!(
        SignedReplicaAck::from_bytes(&zero.to_bytes().unwrap()),
        Err(WireError)
    );
}
