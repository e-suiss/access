use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::verify::key_scope::thumbprint;

fn public(alg: PqAlgorithm) -> Vec<u8> {
    (0..alg.public_key_len())
        .map(|i| u8::try_from(i % 251).unwrap_or_default())
        .collect()
}

// CR-41 m.1, FIPS 204, OP-159 m.3 (c)
#[test]
fn parameter_sets_name_their_cose_and_jose_algorithms_and_lengths() {
    let rows = [
        (PqAlgorithm::MlDsa44, -48, "ML-DSA-44", 1312, 2420),
        (PqAlgorithm::MlDsa65, -49, "ML-DSA-65", 1952, 3309),
        (PqAlgorithm::MlDsa87, -50, "ML-DSA-87", 2592, 4627),
    ];
    for (alg, cose, jose, key, sig) in rows {
        assert_eq!(alg.algorithm().cose(), cose);
        assert_eq!(alg.jose(), jose);
        assert_eq!(alg.public_key_len(), key);
        assert_eq!(alg.signature_len(), sig);
        assert_eq!(PqAlgorithm::of(alg.algorithm()), Some(alg));
    }
    for classical in [Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256] {
        assert_eq!(PqAlgorithm::of(classical), None);
    }
}

// CR-45 RA-7, OP-159 m.3 (h)
#[test]
fn a_pq_anchor_round_trips_and_its_kid_is_the_key_thumbprint() {
    let key = PublicKey::MlDsa(Algorithm::MlDsa65, public(PqAlgorithm::MlDsa65));
    let witness = Witness::new(
        "witness.example".into(),
        PublicKey::MlDsa(Algorithm::MlDsa44, public(PqAlgorithm::MlDsa44)),
        Algorithm::MlDsa44,
        "northwind".into(),
        true,
    );
    let anchor = PqAnchor::new(Digest([3; 32]), thumbprint(&key), key, vec![witness], 77);
    let back = PqAnchor::from_bytes(&anchor.to_bytes().unwrap()).unwrap();
    assert_eq!(back, anchor);
    let mut wrong = anchor.clone();
    wrong.kid = [9; 32];
    assert_eq!(
        PqAnchor::from_bytes(&wrong.to_bytes().unwrap()),
        Err(ModelError::Range)
    );
    let mut none = anchor;
    none.witnesses.clear();
    assert!(PqAnchor::from_bytes(&none.to_bytes().unwrap()).is_err());
}
