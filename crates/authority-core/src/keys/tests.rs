#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

fn row(since: u64, ended: Option<u64>) -> KeyRow {
    let key = PublicKey::Ed25519([9; 32]);
    KeyRow {
        kid: [1; 32],
        instance: [2; 16],
        party: [3; 16],
        public_key: dcbor::encode(&key.to_value(), Limits::CEILING).unwrap(),
        since_pos: since,
        since_at: since.saturating_mul(1_000),
        ended: ended.map(|p| (p, p.saturating_mul(1_000))),
        successor: Some([4; 16]),
        pos: ended.unwrap_or(since),
    }
}

// OP-149 m.5: a key is unknown before its Instance holds it, active while it does and ended
// from the record that ends it; the successor shows only once ended
#[test]
fn a_key_is_read_at_a_ledger_position() {
    let r = row(5, Some(9));
    assert!(entry(&r, 4, &[]).is_none());
    let active = entry(&r, 8, &[]).unwrap();
    assert_eq!(active.state, KeyState::Active);
    assert!(active.ended.is_none() && active.successor.is_none());
    let ended = entry(&r, 9, &[]).unwrap();
    assert_eq!(ended.state, KeyState::Ended);
    assert_eq!(ended.ended, Some(Point { pos: 9, at: 9_000 }));
    assert_eq!(ended.successor, Some(Id([4; 16])));
}

// OP-149 m.5, SEC12, OP-141 m.31: a key set up at or after a declared compromise's occurredAt
// is compromised from the declaration on; an older key is not
#[test]
fn a_compromise_covers_keys_set_up_in_its_window() {
    let c = Compromise {
        from: 4_000,
        claim: Id([7; 16]),
        declared: 12,
        declared_at: 12_000,
    };
    let inside = row(5, None);
    assert_eq!(entry(&inside, 11, &[c]).unwrap().state, KeyState::Active);
    let covered = entry(&inside, 12, &[c]).unwrap();
    assert_eq!(covered.state, KeyState::Compromised);
    assert_eq!(covered.compromise, Some(c));
    let before = row(3, Some(13));
    assert_eq!(entry(&before, 20, &[c]).unwrap().state, KeyState::Ended);
}

// OP-149 m.5, L0-META-6: an Instance state puts its key with its successor and end; a removed
// thumbprint entry ends the key it named; other effects change nothing
#[test]
fn state_effects_become_key_changes() {
    use access_kernel::meta::{Ended, EndedHow};
    let key = PublicKey::Ed25519([9; 32]);
    let state = InstanceState {
        party: Id([3; 16]),
        key: key.clone(),
        since: 5,
        successor: Some(Id([4; 16])),
        ended: Some(Ended {
            at: 9,
            how: EndedHow::Recovered,
        }),
    };
    let Some(KeyChange::Put(r)) = change(
        meta::kind::INSTANCE,
        &[2; 16],
        Some(&state.to_value()),
        9,
        9_000,
    ) else {
        panic!()
    };
    assert_eq!(r.kid, thumbprint(&key));
    assert_eq!((r.instance, r.party, r.since_pos), ([2; 16], [3; 16], 5));
    assert_eq!(r.ended, Some((9, 9_000)));
    assert_eq!(r.successor, Some([4; 16]));
    assert_eq!(
        change(meta::kind::KEY, &[1; 32], None, 7, 7_000),
        Some(KeyChange::End {
            kid: [1; 32],
            pos: 7,
            at: 7_000
        })
    );
    assert_eq!(
        change(
            meta::kind::KEY,
            &[1; 32],
            Some(&Value::Unsigned(1)),
            7,
            7_000
        ),
        None
    );
    assert_eq!(change(meta::kind::GRANT, &[1; 16], None, 7, 7_000), None);
}

// OP-149 m.5: `public_key` is an RFC 9052 COSE_Key and `alg` its COSE algorithm
#[test]
fn keys_are_cose_keys() {
    let ed = dcbor::encode(&cose_key(&PublicKey::Ed25519([9; 32])), Limits::CEILING).unwrap();
    assert_eq!(&ed[..7], &[0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06]);
    assert_eq!(alg(&PublicKey::Ed25519([9; 32])), -19);
    let mut point = vec![4];
    point.extend([1; 32]);
    point.extend([2; 32]);
    let ec = cose_key(&PublicKey::P256(point.clone()));
    let Value::Map(m) = ec else { panic!() };
    assert!(m.contains(&(Value::int(-3), Value::Bytes(vec![2; 32]))));
    assert_eq!(alg(&PublicKey::P256(point)), -9);
}

// OP-149 m.5: the payload is canonical CBOR in the order asked
#[test]
fn the_payload_is_deterministic() {
    let lookup = Lookup {
        domain: Digest([1; 32]),
        pos: 9,
        iat: 9_500,
        keys: vec![entry(&row(5, Some(9)), 9, &[]).unwrap()],
        unknown: vec![[8; 32]],
    };
    let bytes = payload(&lookup);
    assert_eq!(bytes, payload(&lookup.clone()));
    let Value::Map(m) = dcbor::decode(&bytes, Limits::CEILING).unwrap() else {
        panic!()
    };
    assert!(m.contains(&(Value::text("pos"), Value::Unsigned(9))));
}
