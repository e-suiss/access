#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;
use crate::verify::cose::{Algorithm, PublicKey};
use crate::verify::key_scope::{BindingScope, thumbprint};

fn binding() -> BTreeMap<[u8; 32], BindingKey> {
    let key = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[3; 32])
            .verifying_key()
            .to_bytes(),
    );
    let b = BindingKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    };
    BTreeMap::from([(b.kid, b)])
}

fn entry(threshold: u64, hardware: u64) -> RecoveryEntry {
    RecoveryEntry::new(
        threshold,
        [[1; 32], [2; 32], [3; 32]].into_iter().collect(),
        hardware,
        KeyHolding::Device,
        [Id([9; 16])].into_iter().collect(),
    )
}

// SEC20, §13.6, OP-158 m.3 (b)
#[test]
fn a_recovery_entry_round_trips_and_its_ranges_hold() {
    let e = entry(2, 2);
    assert_eq!(RecoveryEntry::from_value(&e.to_value()).unwrap(), e);
    for bad in [entry(0, 2), entry(4, 2), entry(2, 1), entry(2, 4)] {
        assert_eq!(
            RecoveryEntry::from_value(&bad.to_value()),
            Err(ModelError::Range)
        );
    }
}

// SEC21, SEC22, OP-158 m.3 (b)
#[test]
fn recovery_and_handover_inputs_round_trip() {
    let c = CheckpointRef::new(7, Digest([4; 32]));
    let mut r = RecoverInput::new(7, c, BTreeMap::new());
    r.lost_suffix = Some(LostSuffix::new(7, 9));
    r.fork.insert(CheckpointRef::new(8, Digest([5; 32])));
    r.witness_claims.insert(Id([6; 16]));
    assert!(
        RecoverInput::from_value(&r.to_value()).is_err(),
        "a binding is required"
    );
    r.binding = binding();
    assert_eq!(RecoverInput::from_value(&r.to_value()).unwrap(), r);
    let h = HandoverInput::new(binding(), c, true);
    assert_eq!(HandoverInput::from_value(&h.to_value()).unwrap(), h);
    assert!(
        HandoverInput::from_value(&HandoverInput::new(BTreeMap::new(), c, false).to_value())
            .is_err()
    );
    assert_eq!(CheckpointRef::from_value(&c.to_value()).unwrap(), c);
    r.lost_suffix = Some(LostSuffix::new(6, 9));
    assert!(RecoverInput::from_value(&r.to_value()).is_err());
}

// SEC22 R1, TI-RT1, U28
#[test]
fn the_quarantine_patterns_and_the_pre_recovery_subcode_are_named() {
    for q in [Quarantine::PostRecovery, Quarantine::Divergence] {
        assert_eq!(Quarantine::from_name(q.name()), Some(q));
    }
    assert_eq!(Quarantine::from_name("other"), None);
    assert!(PRE_RECOVERY.starts_with("nonce-closed/"));
}
